// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

use crate::db;
use crate::decoy;
use crate::types::*;

use super::super::{build_auth_cookies, AppError, LoginError, MAX_PENDING_CHALLENGES};

/// Normalize a caller-supplied optional username for login lookup: trim,
/// lowercase, and treat an all-whitespace/empty value the same as "absent"
/// so callers don't have to special-case `Some("")`.
#[tracing::instrument(skip_all)]
pub(crate) fn normalize_login_username(username: Option<String>) -> Option<String> {
    username
        .map(|u| u.trim().to_lowercase())
        .filter(|u| !u.is_empty())
}

/// Deserialize a set of stored `public_key` blobs into `SecurityKey`s for use
/// as an `allowCredentials` list.
#[tracing::instrument(skip_all, err)]
fn deserialize_security_keys(public_keys: &[Vec<u8>]) -> Result<Vec<SecurityKey>, anyhow::Error> {
    public_keys
        .iter()
        .enumerate()
        .map(|(i, cred_bytes)| {
            serde_json::from_slice(cred_bytes).map_err(|e| {
                tracing::error!("Failed to deserialize credential {}", i);
                anyhow::anyhow!("Failed to deserialize credential: {}", e)
            })
        })
        .collect()
}

/// Real, throwaway-generated `SecurityKey`s (serialized the same way
/// `finish_securitykey_registration` output is stored — see
/// `finish_passkey_registration_handler`), used ONLY to size decoy-path CPU
/// work to match the real path. Their private key material corresponds to
/// no real user, is never checked against a real challenge, and is never
/// returned to a client. Two algorithms (ES256 and RS256 — the two the
/// gateway's `Webauthn` instance accepts, see `COSEAlgorithm::secure_algs()`
/// / `main.rs`) are alternated in `equalize_decoy_work` so the decoy's
/// per-credential JSON/COSE-deserialize cost isn't systematically cheaper
/// than a real account that holds RSA credentials (whose much larger
/// modulus costs more to base64-decode and parse than an EC point).
const DECOY_TIMING_FIXTURE_ES256: &[u8] = br#"{"cred":{"cred_id":"7ySFchbdsv8y8B5oR-1cxOlY5Trjo1auESH25Co0nTI","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"SveqzIeBhZDl0phwAvHY0rAIEdeTphQu4ReAuCzq8bs","y":"6mm9arrmm2MqgpwkdTvN0-X-cduiZd4zAQdvDuEDO7M"}}},"counter":0,"transports":null,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed"}}"#;
const DECOY_TIMING_FIXTURE_RS256: &[u8] = br#"{"cred":{"cred_id":"Zf6IREgEOMUe8fugN_Td2VjbdNuKDMDBbp3kgUjn4kk","cred":{"type_":"RS256","key":{"RSA":{"n":"BYLwR4Q78LFZmPfF5N_7iQg8FYJ2gB8t7W0Wqtwte6v0-aDMmCNhEu1eikRqosqqPyPOUhSfVy7f8e6gFHGznMhHt7c2IS687B9aH57XV78ySjitd55wLeMhzMdRFZxKcPja1IhyZ_yesU6aJFBWvRujd4Ufqj__WEs4IkJetjeT6KlpBQy67AQozbqcDvtq4NokcpfGLGbimMTEkGMyzARY28jyzgvJj82EZwzUC8LMEa5CYIbKZUIeZwMpaA63OoFexxJt9vCMAPathraD6A4yiwDswJ9bMKekblYDqJBpwAmJFnHK5nEpHNkGkXobhXel5pBw9RJ0DY8cjKe1uA","e":[1,0,1]}}},"counter":0,"transports":null,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed"}}"#;

/// Both decoy timing fixtures, in the order `equalize_decoy_work` alternates
/// them. Panics at process startup (see `validate_decoy_timing_fixtures`,
/// called from `main`) if either ever fails to deserialize, rather than
/// silently degrading the decoy path's timing-equalization at request time.
const DECOY_TIMING_FIXTURES: [&[u8]; 2] = [DECOY_TIMING_FIXTURE_ES256, DECOY_TIMING_FIXTURE_RS256];

/// Called once from `main` at startup: fail fast (panic via `expect`) if
/// either `DECOY_TIMING_FIXTURE_*` constant ever fails to deserialize — e.g.
/// format drift on a future `webauthn-rs` upgrade — rather than letting
/// `equalize_decoy_work`'s per-request fail-open path silently reopen the
/// timing side-channel it exists to close.
#[tracing::instrument(skip_all)]
pub fn validate_decoy_timing_fixtures() {
    for fixture in DECOY_TIMING_FIXTURES {
        deserialize_security_keys(&[fixture.to_vec()])
            .expect("DECOY_TIMING_FIXTURE failed to deserialize at startup");
    }
}

/// Perform throwaway deserialize + auth-challenge-build work on the decoy
/// path, sized to match the real branch's dominant per-credential cost
/// (JSON/COSE deserialize + `start_securitykey_authentication`'s O(N)
/// build), so begin-login response latency stops leaking whether a
/// username exists or how many credentials it has. Alternates the ES256 and
/// RS256 fixtures so the decoy path isn't systematically cheaper than a real
/// account holding RSA credentials. Never stores or returns its result — the
/// real `AuthState::Discoverable{Decoy}` from
/// `start_discoverable_authentication` is what actually gets persisted, so a
/// decoy still can never complete a ceremony. Fails open: both fixtures are
/// validated once at startup (`validate_decoy_timing_fixtures`), so a
/// per-request deserialize error here would mean in-process corruption, not
/// format drift — log and skip rather than fail the login-begin request.
#[tracing::instrument(skip_all)]
fn equalize_decoy_work(state: &AppState, n: usize) {
    let blobs: Vec<Vec<u8>> = (0..n)
        .map(|i| DECOY_TIMING_FIXTURES[i % DECOY_TIMING_FIXTURES.len()].to_vec())
        .collect();
    match deserialize_security_keys(&blobs) {
        Ok(keys) => {
            let result = state.webauthn.start_securitykey_authentication(&keys);
            std::hint::black_box(result);
        }
        Err(e) => {
            tracing::warn!(
                "Decoy timing-equalization fixture failed to deserialize: {:?}",
                e
            );
        }
    }
}

/// Username scope recorded on an `AuthState::Discoverable` challenge, checked
/// against the resolved user at finish time. Only ever meaningfully set by
/// `scoped_or_decoy_challenge` (i.e. a username was supplied for this
/// challenge) — the plain broadcast/discoverable login (no username at all)
/// always uses `Unscoped`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UsernameScope {
    /// No username was supplied for this challenge — any resolved user is
    /// acceptable, since nothing was scoped to begin with.
    Unscoped,
    /// A username was supplied but the challenge is a decoy: either the
    /// username didn't resolve to any user (`expected_user_id: None`) or it
    /// resolved to a user with zero registered credentials
    /// (`expected_user_id: Some`). Either way this challenge must never
    /// successfully authenticate as any user — that's the whole point of a
    /// decoy: it looks identical to a real scoped challenge but can't be
    /// completed.
    Decoy { expected_user_id: Option<Uuid> },
}

/// Verifies a resolved discoverable-auth user is consistent with the
/// username scope recorded when the challenge began (Finding 1: a
/// username-scoped decoy challenge must not silently authenticate whichever
/// resident credential the browser/authenticator happens to return).
#[tracing::instrument(skip_all, err)]
pub(crate) fn check_username_scope(
    scope: &UsernameScope,
    resolved_user_id: Uuid,
) -> Result<(), LoginError> {
    match scope {
        UsernameScope::Unscoped => Ok(()),
        UsernameScope::Decoy { expected_user_id } => {
            if *expected_user_id == Some(resolved_user_id) {
                Ok(())
            } else {
                Err(LoginError::UnexpectedCredentialOwner {
                    expected_user_id: *expected_user_id,
                    actual_user_id: resolved_user_id,
                })
            }
        }
    }
}

/// Overwrite a freshly-started discoverable-auth challenge's client-facing
/// shape to match a real username-scoped challenge, so a decoy is
/// indistinguishable from a real account: a non-empty, per-username-stable,
/// HMAC-synthesized `allowCredentials` list, no `mediation`, and
/// `UserVerificationPolicy::Preferred` — exactly what the real scoped branch
/// of `scoped_or_decoy_challenge` produces. The underlying `auth_state`
/// (the actual server-side challenge from `start_discoverable_authentication`)
/// is untouched and real; only the response sent to the client is reshaped.
/// The synthesized credential IDs never exist in server state, so they can
/// never complete a ceremony — and `check_username_scope` additionally
/// rejects any resident credential a decoy challenge does resolve to.
#[tracing::instrument(skip_all)]
fn apply_decoy_shape(
    rcr: &mut RequestChallengeResponse,
    csrf_secret: &str,
    normalized_username: &str,
) {
    rcr.public_key.allow_credentials =
        decoy::synthesize_allow_credentials(csrf_secret, normalized_username);
    rcr.mediation = None;
    rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
}

/// Start a real (never-completable) discoverable-auth ceremony and reshape
/// its response to the decoy shape via `apply_decoy_shape`, recording
/// `expected_user_id` on the returned `UsernameScope::Decoy` so
/// `check_username_scope` rejects it at finish regardless of which resident
/// credential the browser returns. Shared by both decoy call sites in
/// `scoped_or_decoy_challenge`: the natural decoy (unknown username, or a
/// known username with zero credentials) and the forced decoy (a username
/// that tripped the per-username rate limit, whether or not it's real).
///
/// `equalize` controls whether `equalize_decoy_work` runs: skip it
/// (`false`) only when `username` is provably not a real account by format
/// alone (e.g. fails `validate_username`) — there's no real per-credential
/// cost to match in that case, and it saves the crypto work.
#[tracing::instrument(skip_all, err)]
async fn force_decoy_challenge(
    state: &AppState,
    username: &str,
    expected_user_id: Option<Uuid>,
    equalize: bool,
) -> anyhow::Result<(RequestChallengeResponse, AuthState)> {
    let (mut rcr, auth_state) = state.webauthn.start_discoverable_authentication().map_err(|e| {
        tracing::error!("Failed to start decoy challenge: {:?}", e);
        anyhow::anyhow!("Failed to start authentication: {}", e)
    })?;
    apply_decoy_shape(&mut rcr, &state.csrf_secret, username);
    if equalize {
        equalize_decoy_work(state, rcr.public_key.allow_credentials.len());
    }

    Ok((
        rcr,
        AuthState::Discoverable {
            auth_state,
            scope: UsernameScope::Decoy { expected_user_id },
        },
    ))
}

/// Build a username-scoped `allowCredentials` challenge for a known username
/// with credentials, or a synthesized decoy challenge otherwise (unknown
/// username, or known username with zero registered credentials) — same
/// shape either way (non-empty `allowCredentials`, no `mediation`,
/// `user_verification: Preferred`), so the caller can't use this to
/// enumerate usernames. Shared by the direct login-begin path and the QR
/// cross-device login path.
///
/// Format pre-check (before rate limiting or DB work): a username that
/// fails `validate_username` (too short/long, disallowed characters) can
/// never belong to a real account — registration enforces the same rule —
/// so there is no real per-credential cost to equalize against and no
/// benefit to spending a per-username rate-limit bucket on it (that map is
/// keyed by raw username string, so accepting arbitrary garbage here would
/// let a prober grow it unboundedly). Route straight to the same decoy
/// shape everything else gets, skipping `equalize_decoy_work`.
///
/// Per-username rate limiting (enumeration defense item #3): before doing
/// ANY DB work, check `state.username_begin_limiter` keyed by the
/// (already-normalized) username. If that username has been requested too
/// many times in the window, short-circuit straight to a forced decoy
/// (`force_decoy_challenge`) WITHOUT touching the DB — this deliberately
/// runs ahead of the real-vs-decoy branching below so a flooded username
/// (real or not) always degrades to "looks real but can never
/// authenticate" rather than a hard error. Because this check lives inside
/// `scoped_or_decoy_challenge` rather than in `begin_login_handler`, the QR
/// cross-device begin path (`qr_login_authenticate_handler`, which also
/// calls this function) inherits the same per-username cap automatically.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn scoped_or_decoy_challenge(
    state: &AppState,
    username: &str,
) -> anyhow::Result<(RequestChallengeResponse, AuthState)> {
    if crate::validation::validate_username(username).is_err() {
        return force_decoy_challenge(state, username, None, false).await;
    }

    if !state.username_begin_limiter.check_rate_limit(username).await {
        tracing::warn!(
            "Per-username begin-login rate limit exceeded; forcing decoy response"
        );
        return force_decoy_challenge(state, username, None, true).await;
    }

    let user_id = db::get_user_id_by_username(&state.db, username).await?;

    // Timing equalization: always issue the same shape of DB work (a user
    // lookup followed by a credential fetch keyed on a real/plausible user
    // id) regardless of whether the username resolved, so the number and
    // kind of DB round trips can't themselves leak existence over a timing
    // side-channel. For an unknown username there's no real user id to
    // fetch credentials for, so we query a random UUID instead — it can
    // never match a row in `fido2_credentials` (whose `user_id` is a real
    // FK), so the query costs the same indexed lookup and returns empty,
    // and the result is discarded.
    //
    // SCOPE OF THIS EQUALIZATION: it only equalizes the *DB round trips*
    // (count and kind of queries) on a single gateway replica/process. The
    // dominant remaining CPU cost is `deserialize_security_keys` over N
    // credential blobs plus `start_securitykey_authentication`'s O(N) build:
    // the real-user branch below runs that over the user's actual credential
    // blobs, while the decoy branch (`force_decoy_challenge` ->
    // `equalize_decoy_work`) now runs the SAME deserialize + auth-build work
    // over N copies of a throwaway fixture (`DECOY_TIMING_FIXTURE`), sized to
    // the same allowCredentials count the decoy shape advertises — closing
    // the gap for that dominant cost. This is still not a hard constant-time
    // guarantee overall: scheduler/OS-level jitter, cache effects, and other
    // lower-order timing sources remain out of scope.
    let credential_lookup_id = user_id.unwrap_or_else(Uuid::new_v4);
    let public_keys = db::get_credential_public_keys_by_user_id(&state.db, credential_lookup_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch credentials for scoped login: {:?}", e);
            anyhow::anyhow!("Failed to fetch credentials: {}", e)
        })?;
    let allow_credentials = match user_id {
        Some(_) => deserialize_security_keys(&public_keys)?,
        None => Vec::new(),
    };

    if user_id.is_some() && !allow_credentials.is_empty() {
        tracing::debug!(
            "Starting username-scoped authentication challenge with {} credentials",
            allow_credentials.len()
        );

        let (mut rcr, auth_state) = state
            .webauthn
            .start_securitykey_authentication(&allow_credentials)
            .map_err(|e| {
                tracing::error!("Failed to start scoped authentication: {:?}", e);
                anyhow::anyhow!("Failed to start authentication: {}", e)
            })?;
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
        return Ok((rcr, AuthState::SecurityKey(auth_state)));
    }

    // Decoy path: either the username doesn't resolve to any user, or it
    // resolves to a user with zero registered credentials. Both cases are
    // indistinguishable from each other AND from the real scoped response
    // above — same non-empty `allowCredentials` shape, no `mediation`,
    // Preferred UV. `force_decoy_challenge` starts a real server-side
    // challenge + state (so a probing client can't tell this apart from a
    // real ceremony start) and reshapes the client-facing response.
    // `expected_user_id` is either no such user (`None`) or the user is
    // known but has zero credentials (`Some`) — either way finish must
    // always reject, regardless of which resident credential the browser
    // returns.
    force_decoy_challenge(state, username, user_id, true).await
}

/// `POST /auth/login/begin`. Tolerates an absent/empty JSON body (treated as
/// `{ "username": null }`) since axum's `Json` extractor rejects those.
///
/// - `username` present & non-empty, and matches a user with ≥1 registered
///   credential -> username-scoped `allowCredentials` (that user's
///   credentials only), no `mediation`, `user_verification: Preferred`.
/// - `username` present & non-empty, but no such user, or a known user with
///   zero credentials -> a decoy challenge with the SAME shape: a non-empty,
///   deterministically HMAC-synthesized `allowCredentials` list (see
///   `decoy::synthesize_allow_credentials`), no `mediation`,
///   `user_verification: Preferred`. Never a 404, and never distinguishable
///   by shape from the real-user case above — the existence of the username
///   is unanswerable from this response. The synthesized IDs never exist in
///   server state, so a decoy can never complete a ceremony
///   (`check_username_scope` enforces this at finish).
/// - `username` absent/empty:
///   - `login_allow_broadcast == true` (default) -> legacy broadcast:
///     `allowCredentials` = every credential in the DB, byte-for-byte
///     unchanged behavior.
///   - `login_allow_broadcast == false` -> discoverable: empty
///     `allowCredentials`, `mediation: "conditional"` (set automatically by
///     `start_discoverable_authentication`).
#[tracing::instrument(skip_all, err(Debug))]
pub async fn begin_login_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let username: Option<String> = normalize_login_username(if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<LoginBeginRequest>(&body)
            .ok()
            .and_then(|r| r.username)
    });

    let (rcr, auth_state) = if let Some(username) = username {
        // Tighter per-IP budget on top of the blanket global limiter (item
        // #3 of the enumeration defense): a scoped-begin request does more
        // per-call work (a DB lookup) than a plain broadcast begin, and is
        // the shape an enumeration attacker actually wants to spam. A hard
        // 429 here is safe — it's keyed by IP, not by username, so it can't
        // leak whether any particular username exists.
        if !state
            .scoped_begin_limiter
            .check_rate_limit(&addr.ip().to_string())
            .await
        {
            tracing::warn!("Scoped begin-login rate limit exceeded for IP: {}", addr.ip());
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response());
        }

        // Username-scoped fallback path (e.g. CLI / non-resident keys).
        // `scoped_or_decoy_challenge` additionally enforces a per-username
        // budget and forces a decoy (never a 429) once that's exceeded.
        scoped_or_decoy_challenge(&state, &username).await?
    } else if state.login_allow_broadcast {
        // Legacy behavior: broadcast every credential in the DB. Kept
        // byte-for-byte unchanged pending the Phase 3 flip.
        let all_public_keys = db::get_all_credential_public_keys(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch credentials from DB: {:?}", e);
                anyhow::anyhow!("Failed to fetch credentials: {}", e)
            })?;

        tracing::debug!("Found {} credentials in database", all_public_keys.len());

        let allow_credentials = deserialize_security_keys(&all_public_keys)?;

        tracing::debug!(
            "Starting authentication challenge with {} credentials",
            allow_credentials.len()
        );

        // Use securitykey auth which allows flexible UV policy (unlike passkey which requires UV)
        let (mut rcr, auth_state) = state
            .webauthn
            .start_securitykey_authentication(&allow_credentials)
            .map_err(|e| {
                tracing::error!("Failed to start authentication: {:?}", e);
                anyhow::anyhow!("Failed to start authentication: {}", e)
            })?;

        // Always use Preferred - we enforce PIN requirement in finish_login based on org settings
        // This allows the authenticator to decide, and we validate server-side
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;

        tracing::debug!(
            "Authentication challenge created for RP {} with {} allowed credentials",
            rcr.public_key.rp_id,
            rcr.public_key.allow_credentials.len()
        );

        (rcr, AuthState::SecurityKey(auth_state))
    } else {
        // Primary path: username-less discoverable / conditional UI login.
        let (rcr, auth_state) = state.webauthn.start_discoverable_authentication().map_err(|e| {
            tracing::error!("Failed to start discoverable authentication: {:?}", e);
            anyhow::anyhow!("Failed to start authentication: {}", e)
        })?;
        (
            rcr,
            AuthState::Discoverable {
                auth_state,
                scope: UsernameScope::Unscoped,
            },
        )
    };

    let session_key = Uuid::new_v4().to_string();
    let pending = PendingAuthentication {
        auth_state,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
    };
    {
        let mut auth_states = state.auth_states.write().await;
        if auth_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(anyhow::anyhow!("Too many pending logins").into());
        }
        auth_states.insert(session_key.clone(), pending);
    }

    Ok(Json(LoginBeginResponse {
        challenge: rcr,
        session: session_key,
    })
    .into_response())
}

#[tracing::instrument(skip_all, err)]
pub async fn finish_login_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, LoginError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LoginError::InvalidSession("missing session field".into()))?
        .to_string();

    // Remove (rather than read+clone then remove) so this is the single
    // source of truth for challenge consumption — a session can only be
    // finished once, and we don't need `AuthState` to be droppable-and-reused.
    let pending = {
        let mut auth_states = state.auth_states.write().await;
        auth_states.remove(&session_key)
    }
    .ok_or_else(|| LoginError::InvalidSession(session_key.clone()))?;

    // Check if the authentication challenge has expired.
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(LoginError::ChallengeExpired);
    }

    let auth_response: PublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|source| LoginError::ParsePubkeyCredential { source })?;

    tracing::debug!("Received authentication response");

    let (user_id, credential_id_bytes, mut seckey, auth_result) = match pending.auth_state {
        AuthState::SecurityKey(auth_state) => {
            // Legacy / username-scoped path: resolve the user from the
            // asserted credential's rawId, exactly as before.
            let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
            tracing::debug!("Credential ID: {}", hex::encode(&credential_id_bytes));

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            tracing::debug!("Credential fetched, performing securitykey authentication");

            let auth_result = state
                .webauthn
                .finish_securitykey_authentication(&auth_response, &auth_state)
                .map_err(|source| LoginError::FinishSecurityKeyAuthentication { user_id, source })?;

            (user_id, credential_id_bytes, seckey, auth_result)
        }
        AuthState::Discoverable { auth_state, scope } => {
            // Primary path: resolve the user from the assertion's userHandle,
            // then reload the credential by its rawId to reuse the rest of
            // the (PIN check / counter update / session creation) pipeline
            // unchanged.
            let (_user_handle, cred_id) = state
                .webauthn
                .identify_discoverable_authentication(&auth_response)
                .map_err(|source| LoginError::IdentifyDiscoverableCredential { source })?;
            let credential_id_bytes = cred_id.to_vec();
            tracing::debug!(
                "Discoverable credential ID: {}",
                hex::encode(&credential_id_bytes)
            );

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            // SecurityKey -> Credential -> Passkey -> DiscoverableKey, per
            // webauthn-rs 0.5's discoverable-auth API (needs the
            // `danger-credential-internals` feature for the Credential
            // conversions).
            let credential: Credential = seckey.clone().into();
            let passkey: Passkey = credential.into();
            let discoverable_key: DiscoverableKey = passkey.into();

            tracing::debug!("Credential fetched, performing discoverable authentication");

            let auth_result = state
                .webauthn
                .finish_discoverable_authentication(&auth_response, auth_state, &[discoverable_key])
                .map_err(|source| LoginError::FinishDiscoverableAuthentication { user_id, source })?;

            // Ceremony is consumed (challenge validated) at this point even
            // if the scope check below rejects it, so a decoy challenge can't
            // be completed by authenticating as a different resident user
            // (Finding 1). The rejection is intentionally byte-for-byte
            // identical to every other credential-verification failure (see
            // `LoginError::into_response`) to avoid a username-enumeration
            // oracle.
            check_username_scope(&scope, user_id)?;

            // Opportunistic residency backfill: a successful discoverable
            // finish proves the authenticator surfaced this credential via
            // userHandle, i.e. it's resident. Best-effort — never fail the
            // login over this.
            if let Err(e) =
                db::mark_credential_resident_if_unknown(&state.db, &credential_id_bytes).await
            {
                tracing::warn!("Failed to backfill credential resident flag: {:?}", e);
            }

            (user_id, credential_id_bytes, seckey, auth_result)
        }
    };

    tracing::debug!(
        user_verified = auth_result.user_verified(),
        "Authentication successful"
    );

    // Check if user's org requires PIN verification.
    let requires_pin = db::user_requires_pin(&state.db, user_id)
        .await
        .map_err(|source| LoginError::DbUserPinRequired { user_id, source })?;
    if requires_pin && !auth_result.user_verified() {
        tracing::warn!(
            "User {} login rejected: org requires PIN but user_verified=false",
            user_id
        );
        return Err(LoginError::PinRequired);
    }

    if auth_result.needs_update() {
        let update_result = seckey.update_credential(&auth_result);

        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&seckey)
                .map_err(|source| LoginError::SerializeSecurityKey { user_id, source })?;

            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await
            .map_err(|source| LoginError::DbUpdateFido2Credential { user_id, source })?;
        }
    }

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at)
        .await
        .map_err(|source| LoginError::DbCreateAuthSession { user_id, source })?;

    let credential_id_hex = hex::encode(&credential_id_bytes);
    tracing::debug!(
        "Login complete (session expires in {} hours)",
        state.session_timeout_hours
    );

    // Build the response (session_id is in Set-Cookie header, not body)
    let response_body = LoginFinishResponse {
        expires_at: expires_at.to_string(),
        credential_id: credential_id_hex,
    };

    // Check if we're in production (HTTPS) - use secure cookies
    let secure = std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_auth_cookies(
        &session_id,
        &csrf_token,
        state.session_timeout_hours,
        secure,
    );

    let body = serde_json::to_string(&response_body)
        .map_err(|source| LoginError::SerializeLoginFinishResponse { user_id, source })?;

    // Use HeaderMap with append to properly set multiple Set-Cookie headers
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).unwrap(),
    );

    Ok((StatusCode::OK, headers, body).into_response())
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn logout_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    // Get session from header (CLI) or cookie (browser)
    let session_id = headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| crate::csrf::get_cookie(&headers, "caution_session"));

    // Delete session from database if we found one
    let mut deletion_failed = false;
    if let Some(session_id) = session_id {
        if let Err(e) = db::delete_auth_session(&state.db, &session_id).await {
            tracing::error!("Failed to delete session during logout: {:?}", e);
            deletion_failed = true;
        }
    }

    // Build response with cleared cookies (clear even on error so client is logged out)
    let secure = std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_logout_cookies(secure);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).unwrap(),
    );

    if deletion_failed {
        Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            r#"{"error":"Failed to delete session"}"#,
        )
            .into_response())
    } else {
        Ok((StatusCode::OK, headers, r#"{"status":"logged_out"}"#).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs_proto::Mediation;

    // --- normalize_login_username -------------------------------------
    //
    // These are the pure pieces of the `begin_login_handler` username
    // branching that don't need a DB or a webauthn ceremony, so they're
    // covered here as plain unit tests. The DB-backed branches (scoped
    // lookup returns only that user's creds, broadcast-vs-discoverable
    // selection driven by `login_allow_broadcast`, unknown username ->
    // empty allowCredentials with 200, discoverable finish round-trip via
    // `identify_discoverable_authentication` / `finish_discoverable_authentication`,
    // and the username-claim gate end-to-end) require a live Postgres
    // instance and a webauthn ceremony (or a stored/replayed one) to
    // exercise meaningfully. This crate has no `#[sqlx::test]`/ephemeral-DB
    // harness wired up today (no other test in `gateway` hits a live DB —
    // see `db.rs`'s and `rate_limit.rs`'s test modules, which are all
    // pure/in-memory), and no Postgres is available in this sandbox to add
    // and validate one. Those scenarios are best covered as gateway.rs
    // integration/e2e coverage (following the shell-script pattern under
    // `tests/e2e/*.sh`, run via `make up-test` per the caution-local-dev
    // skill) — flagged here rather than left silently uncovered.

    #[test]
    fn normalizes_present_username() {
        assert_eq!(
            normalize_login_username(Some("  Alice  ".to_string())),
            Some("alice".to_string())
        );
    }

    #[test]
    fn treats_empty_string_as_absent() {
        assert_eq!(normalize_login_username(Some("".to_string())), None);
    }

    #[test]
    fn treats_whitespace_only_as_absent() {
        assert_eq!(normalize_login_username(Some("   ".to_string())), None);
    }

    #[test]
    fn absent_stays_absent() {
        assert_eq!(normalize_login_username(None), None);
    }

    #[test]
    fn lowercases_mixed_case() {
        assert_eq!(
            normalize_login_username(Some("BoB".to_string())),
            Some("bob".to_string())
        );
    }

    // --- deserialize_security_keys -------------------------------------

    #[test]
    fn deserialize_security_keys_empty_list_is_ok() {
        let result = deserialize_security_keys(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn deserialize_security_keys_rejects_garbage() {
        let garbage = vec![b"not valid json".to_vec()];
        assert!(deserialize_security_keys(&garbage).is_err());
    }

    // --- check_username_scope -------------------------------------------
    //
    // Guards the discoverable-auth finish paths against resolving to a user
    // other than the one a username-scoped challenge expected (Finding 1:
    // decoy/zero-cred challenges must not silently authenticate whichever
    // resident credential the browser happens to return). `Unscoped` (no
    // username was ever supplied — plain broadcast/discoverable login) must
    // allow any resolved user; `Decoy` (a username was supplied, whether
    // unknown or known-zero-cred) must never succeed.

    #[test]
    fn check_username_scope_allows_unscoped_login() {
        let resolved = Uuid::new_v4();
        assert!(check_username_scope(&UsernameScope::Unscoped, resolved).is_ok());
    }

    #[test]
    fn check_username_scope_rejects_decoy_for_unknown_username() {
        // Username didn't resolve to any user at all: no expected_user_id,
        // but must still always reject, not just no-op like `Unscoped`.
        let resolved = Uuid::new_v4();
        let err = check_username_scope(&UsernameScope::Decoy { expected_user_id: None }, resolved)
            .unwrap_err();
        assert!(matches!(
            err,
            LoginError::UnexpectedCredentialOwner { expected_user_id: None, actual_user_id }
            if actual_user_id == resolved
        ));
    }

    #[test]
    fn check_username_scope_rejects_decoy_for_known_zero_cred_user_mismatch() {
        let expected = Uuid::new_v4();
        let resolved = Uuid::new_v4();
        let err = check_username_scope(
            &UsernameScope::Decoy { expected_user_id: Some(expected) },
            resolved,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            LoginError::UnexpectedCredentialOwner { expected_user_id: Some(e), actual_user_id }
            if e == expected && actual_user_id == resolved
        ));
    }

    #[test]
    fn check_username_scope_allows_decoy_matching_expected_user() {
        // Can't practically happen (the zero-cred decoy's user has no
        // credentials to resolve to), but if the expected user ever does
        // match the resolved one, it should be honored rather than rejected.
        let user = Uuid::new_v4();
        assert!(
            check_username_scope(&UsernameScope::Decoy { expected_user_id: Some(user) }, user)
                .is_ok()
        );
    }

    // --- apply_decoy_shape -----------------------------------------------
    //
    // `scoped_or_decoy_challenge` itself needs a live Postgres + a real
    // `Webauthn` instance (see the DB-backed-branches note above), but the
    // decoy *response-shaping* step it delegates to is pure: it just
    // mutates an already-built `RequestChallengeResponse`. That's covered
    // directly here without needing a DB or a webauthn ceremony, which is
    // what actually enforces the closed oracle: after this call, a
    // known-with-credentials response and a decoy response must be
    // byte-for-byte identical in shape (non-empty allowCredentials, no
    // mediation, Preferred UV).

    fn dummy_discoverable_rcr() -> RequestChallengeResponse {
        // Mirrors what `start_discoverable_authentication` hands back
        // before `apply_decoy_shape` overwrites it: empty allowCredentials
        // and `mediation: Conditional`.
        RequestChallengeResponse {
            public_key: webauthn_rs_proto::PublicKeyCredentialRequestOptions {
                challenge: vec![0u8; 32].into(),
                timeout: None,
                rp_id: "example.com".to_string(),
                allow_credentials: Vec::new(),
                user_verification: UserVerificationPolicy::Required,
                hints: None,
                extensions: None,
            },
            mediation: Some(Mediation::Conditional),
        }
    }

    #[test]
    fn apply_decoy_shape_produces_non_empty_allow_credentials() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert!(!rcr.public_key.allow_credentials.is_empty());
    }

    #[test]
    fn apply_decoy_shape_clears_mediation() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert!(rcr.mediation.is_none());
    }

    #[test]
    fn apply_decoy_shape_sets_preferred_user_verification() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);
    }

    #[test]
    fn apply_decoy_shape_stable_across_calls_for_same_username() {
        let mut a = dummy_discoverable_rcr();
        let mut b = dummy_discoverable_rcr();
        apply_decoy_shape(&mut a, "secret", "alice");
        apply_decoy_shape(&mut b, "secret", "alice");
        let ids_a: Vec<_> = a.public_key.allow_credentials.iter().map(|c| c.id.as_ref().to_vec()).collect();
        let ids_b: Vec<_> = b.public_key.allow_credentials.iter().map(|c| c.id.as_ref().to_vec()).collect();
        assert_eq!(ids_a, ids_b, "decoy for a given username must be stable across calls");
    }

    #[test]
    fn apply_decoy_shape_matches_real_scoped_response_shape() {
        // Simulates the real-user branch's shape: non-empty allowCredentials,
        // no mediation, Preferred UV — built independently of
        // `apply_decoy_shape` to assert the two are indistinguishable.
        let mut real = dummy_discoverable_rcr();
        real.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
            type_: "public-key".to_string(),
            id: vec![1, 2, 3].into(),
            transports: None,
        }];
        real.mediation = None;
        real.public_key.user_verification = UserVerificationPolicy::Preferred;

        let mut decoy_rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut decoy_rcr, "secret", "someone");

        assert!(!real.public_key.allow_credentials.is_empty());
        assert!(!decoy_rcr.public_key.allow_credentials.is_empty());
        assert_eq!(real.mediation.is_none(), decoy_rcr.mediation.is_none());
        assert!(decoy_rcr.mediation.is_none());
        assert_eq!(
            real.public_key.user_verification,
            decoy_rcr.public_key.user_verification
        );
    }

    #[test]
    fn decoy_timing_fixtures_round_trip_through_deserialize_security_keys() {
        // Guards against future format drift (e.g. a webauthn-rs upgrade
        // changing `SecurityKey`'s serde shape) silently breaking
        // `equalize_decoy_work` in CI before `validate_decoy_timing_fixtures`
        // would catch it at startup in a real deployment.
        for fixture in DECOY_TIMING_FIXTURES {
            assert!(deserialize_security_keys(&[fixture.to_vec()]).is_ok());
        }
    }

    #[test]
    fn validate_decoy_timing_fixtures_does_not_panic() {
        validate_decoy_timing_fixtures();
    }

    // --- per-username rate limiting (enumeration defense item #3) --------
    //
    // `scoped_or_decoy_challenge` checks `state.username_begin_limiter`
    // BEFORE any DB work, so the forced-decoy branch is exercisable without
    // a live Postgres: build an `AppState` around a lazy (never-connecting)
    // pool via `PgPoolOptions::connect_lazy`, which is safe here specifically
    // because a tripped username limiter short-circuits before the first
    // query would ever be issued.

    fn test_app_state(username_limiter_max: u32) -> AppState {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let rp_origin = Url::parse("https://example.com").unwrap();
        let webauthn = WebauthnBuilder::new("example.com", &rp_origin)
            .unwrap()
            .rp_name("Test RP")
            .build()
            .unwrap();
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/nonexistent")
            .expect("connect_lazy does not actually connect");

        AppState {
            db,
            webauthn,
            relying_party_id: "example.com".to_string(),
            api_service_url: String::new(),
            metering_service_url: String::new(),
            http_client: reqwest::Client::new(),
            reg_states: Arc::new(RwLock::new(HashMap::new())),
            passkey_reg_states: Arc::new(RwLock::new(HashMap::new())),
            auth_states: Arc::new(RwLock::new(HashMap::new())),
            sign_challenges: Arc::new(RwLock::new(HashMap::new())),
            session_timeout_hours: 24,
            internal_service_secret: None,
            csrf_secret: "test-secret".to_string(),
            login_allow_broadcast: true,
            scoped_begin_limiter: crate::rate_limit::RateLimiter::new(1000, 60),
            username_begin_limiter: crate::rate_limit::RateLimiter::new(username_limiter_max, 60),
        }
    }

    #[tokio::test]
    async fn username_limiter_trips_after_budget_exhausted() {
        let state = test_app_state(3);

        for _ in 0..3 {
            assert!(state.username_begin_limiter.check_rate_limit("alice").await);
        }
        assert!(!state.username_begin_limiter.check_rate_limit("alice").await);
    }

    #[tokio::test]
    async fn username_limiter_is_independent_per_username() {
        let state = test_app_state(1);

        assert!(state.username_begin_limiter.check_rate_limit("alice").await);
        assert!(!state.username_begin_limiter.check_rate_limit("alice").await);

        // "bob" has his own untouched budget.
        assert!(state.username_begin_limiter.check_rate_limit("bob").await);
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_forces_decoy_when_username_limiter_exceeded() {
        // Budget of 1: the first call is allowed through to the (never
        // reached, thanks to the lazy pool) DB path; the second call must
        // be forced to a decoy WITHOUT touching the DB.
        let state = test_app_state(1);

        // Exhaust the budget directly rather than via a real DB-backed call.
        assert!(state.username_begin_limiter.check_rate_limit("realuser").await);
        assert!(!state.username_begin_limiter.check_rate_limit("realuser").await);

        let (rcr, auth_state) = scoped_or_decoy_challenge(&state, "realuser")
            .await
            .expect("forced decoy must not touch the DB and so must not error");

        assert!(
            !rcr.public_key.allow_credentials.is_empty(),
            "forced decoy must still carry a non-empty allowCredentials list"
        );
        assert!(rcr.mediation.is_none());
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);

        match auth_state {
            AuthState::Discoverable { scope, .. } => {
                assert!(
                    matches!(scope, UsernameScope::Decoy { expected_user_id: None }),
                    "a forced decoy never did the DB lookup, so expected_user_id must be None"
                );
            }
            AuthState::SecurityKey(_) => {
                panic!("forced decoy must never produce a real SecurityKey auth state")
            }
        }
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_forced_decoy_matches_natural_decoy_shape() {
        // The forced-decoy response (limiter tripped) must be shape-identical
        // to the natural decoy response `apply_decoy_shape` produces
        // (non-empty allowCredentials, no mediation, Preferred UV) — an
        // observer must not be able to tell "rate limited" apart from
        // "unknown username" apart from "known but zero creds".
        let state = test_app_state(1);
        assert!(state.username_begin_limiter.check_rate_limit("someone").await);
        assert!(!state.username_begin_limiter.check_rate_limit("someone").await);

        let (forced_rcr, _) = scoped_or_decoy_challenge(&state, "someone").await.unwrap();

        let mut natural_rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut natural_rcr, &state.csrf_secret, "someone");

        assert_eq!(
            forced_rcr.public_key.allow_credentials.len(),
            natural_rcr.public_key.allow_credentials.len()
        );
        assert_eq!(forced_rcr.mediation.is_none(), natural_rcr.mediation.is_none());
        assert_eq!(
            forced_rcr.public_key.user_verification,
            natural_rcr.public_key.user_verification
        );
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_invalid_username_format_still_returns_decoy_shape() {
        // A username that fails `validate_username` (too short here) can
        // never be a real account, so this must short-circuit to a decoy
        // WITHOUT touching the per-username limiter or the (never-connecting)
        // DB pool, while still returning the same shape as every other decoy.
        let state = test_app_state(1000);

        let (rcr, auth_state) = scoped_or_decoy_challenge(&state, "ab")
            .await
            .expect("invalid-format username must not touch the DB and so must not error");

        assert!(!rcr.public_key.allow_credentials.is_empty());
        assert!(rcr.mediation.is_none());
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);

        match auth_state {
            AuthState::Discoverable { scope, .. } => {
                assert!(matches!(scope, UsernameScope::Decoy { expected_user_id: None }));
            }
            AuthState::SecurityKey(_) => {
                panic!("invalid-format username must never produce a real SecurityKey auth state")
            }
        }

        // The per-username limiter budget must be untouched by the
        // format-invalid short-circuit (it never got a chance to grow the
        // limiter's key space for this garbage username).
        assert!(
            state.username_begin_limiter.check_rate_limit("ab").await,
            "format short-circuit must not have consumed a rate-limit slot for this username"
        );
    }
}

/// Build cookies that clear auth state (for logout)
#[tracing::instrument(skip_all)]
fn build_logout_cookies(secure: bool) -> (String, String) {
    // Set cookies with immediate expiration to clear them
    let session_cookie = Cookie::build(("caution_session", ""))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::ZERO)
        .build();

    let csrf_cookie = Cookie::build(("caution_csrf", ""))
        .path("/")
        .http_only(false)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::ZERO)
        .build();

    (session_cookie.to_string(), csrf_cookie.to_string())
}

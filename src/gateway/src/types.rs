// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Extension type set by auth middleware to communicate the authenticated user ID
/// to downstream handlers. Using extensions instead of headers prevents spoofing
/// on routes where auth middleware may not run.
#[derive(Clone)]
pub struct AuthenticatedUserId(pub Uuid);

/// Registration state for account creation.
#[derive(Clone)]
pub enum PendingRegistrationKind {
    AlphaCode {
        alpha_code_id: Uuid,
    },
    OrganizationInvite {
        invitation_id: Uuid,
        token_hash: String,
    },
}

/// Audit record created by the signing middleware for the verified request.
/// Downstream handlers use this extension to link the resulting state change
/// to the exact WebAuthn authorization that permitted it.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedSignedRequestId(pub Uuid);

/// Registration state that records which signup path created the challenge.
#[derive(Clone)]
pub struct PendingRegistration {
    pub reg_state: SecurityKeyRegistration,
    pub kind: PendingRegistrationKind,
    pub username: String,
    pub expires_at: time::OffsetDateTime,
}

/// Registration state for adding an additional passkey to an existing account.
#[derive(Clone)]
pub struct PendingPasskeyRegistration {
    pub reg_state: SecurityKeyRegistration,
    pub user_id: Uuid,
    pub name: Option<String>,
    pub expires_at: time::OffsetDateTime,
}

/// Which webauthn-rs authentication ceremony a pending `/auth/login` challenge is
/// running. `SecurityKey` covers both legacy broadcast and username-scoped login
/// (both resolve the user from the asserted credential's `rawId`). `Discoverable`
/// covers the username-less conditional-UI flow (resolves the user from the
/// assertion's `userHandle` via `identify_discoverable_authentication`).
///
/// Sign flows (`PendingSignChallenge`) are already scoped to a single credential
/// and are intentionally NOT part of this enum — they stay on
/// `SecurityKeyAuthentication` per the Phase 1 design doc.
#[derive(Clone)]
pub enum AuthState {
    SecurityKey(SecurityKeyAuthentication),
    Discoverable {
        auth_state: DiscoverableAuthentication,
        /// Whether this challenge was scoped to a specific username, and if
        /// so which user (or the decoy indicating none). See
        /// `handlers::UsernameScope` / `handlers::check_username_scope`,
        /// checked at finish time so a decoy challenge can't be completed by
        /// authenticating as a different resident user.
        scope: crate::handlers::UsernameScope,
    },
}

/// Authentication state with expiration
#[derive(Clone)]
pub struct PendingAuthentication {
    pub auth_state: AuthState,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub webauthn: Webauthn,
    pub relying_party_id: String,
    pub api_service_url: String,
    pub metering_service_url: String,
    pub reg_states: Arc<RwLock<HashMap<String, PendingRegistration>>>,
    pub passkey_reg_states: Arc<RwLock<HashMap<String, PendingPasskeyRegistration>>>,
    pub auth_states: Arc<RwLock<HashMap<String, PendingAuthentication>>>,
    pub sign_challenges: Arc<RwLock<HashMap<String, PendingSignChallenge>>>,
    pub session_timeout_hours: i64,
    pub internal_service_secret: Option<String>,
    pub csrf_secret: String,
    /// Kill-switch for the legacy credential-broadcast login behavior
    /// (`/auth/login/begin` and `/auth/qr-login/authenticate` with no username
    /// returning every credential in the DB as `allowCredentials`). Defaults to
    /// `true` so nothing regresses mid-migration; flip to `false` via the
    /// `LOGIN_ALLOW_BROADCAST` env var once clients no longer depend on it.
    /// Toggling requires setting the env var and restarting the gateway — it is
    /// read once at startup, not re-read per request.
    pub login_allow_broadcast: bool,
    /// Per-IP budget on username-scoped `begin` requests, on top of the
    /// blanket global limiter. In-memory/single-replica; see
    /// `rate_limit.rs`. Exceeding it returns a hard 429 (safe: keyed by IP,
    /// not username).
    pub scoped_begin_limiter: crate::rate_limit::RateLimiter,
    /// Per-username budget on scoped `begin` requests. In-memory/
    /// single-replica; see `rate_limit.rs`. Exceeding it forces a decoy
    /// response rather than a 429 (see `handlers::scoped_or_decoy_challenge`).
    pub username_begin_limiter: crate::rate_limit::RateLimiter,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbUser {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub fido2_user_handle: Option<Vec<u8>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_type: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transport: Option<sqlx::types::JsonValue>,
    pub flags: Option<sqlx::types::JsonValue>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbSession {
    pub session_id: String,
    pub credential_id: Vec<u8>,
    pub expires_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
    pub last_used_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponseRaw,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponseRaw {
    pub attestation_object: String,
    pub client_data_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    pub status: String,
    pub credential_id: String,
    // Session ID is NOT included in body - it's in Set-Cookie header
    // This prevents XSS from exfiltrating the session
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginBeginResponse {
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
    pub session: String,
}

/// Optional body for `POST /auth/login/begin`. An absent/empty body is
/// tolerated by the handler and treated identically to `{ "username": null }`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LoginBeginRequest {
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponseRaw,
    #[serde(rename = "type")]
    pub type_: String,
    pub session: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponseRaw {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    // Session ID is NOT included in body - it's in Set-Cookie header
    // This prevents XSS from exfiltrating the session
    pub expires_at: String,
    pub credential_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterBeginRequest {
    pub alpha_code: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvitePreviewQuery {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteRegisterBeginRequest {
    pub token: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvitePreviewResponse {
    pub email: String,
    pub organization_name: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub passkey_authentication: PasskeyAuthentication,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedRequestFlow {
    Direct,
    CrossDeviceQr,
}

impl SignedRequestFlow {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::CrossDeviceQr => "cross_device_qr",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingSignChallenge {
    pub challenge_id: Uuid,
    pub auth_state: SecurityKeyAuthentication,
    pub user_id: Uuid,
    pub method: String,
    pub path: String,
    pub body_hash: String,
    pub flow: SignedRequestFlow,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignChallengeRequest {
    pub method: String,
    pub path: String,
    pub body_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignChallengeResponse {
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
    pub challenge_id: String,
}

// QR Login types

/// QR login token status.
///
/// DB stores only: Pending, Authenticated, Completed.
/// Expired and NotFound are derived in handlers (from expires_at timestamp
/// and row absence respectively).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrStatus {
    Pending,
    Authenticated,
    Completed,
    Expired,
    NotFound,
}

impl QrStatus {
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "authenticated" => Some(Self::Authenticated),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrLoginBeginResponse {
    pub token: String,
    pub url: String,
    pub expires_at: String,
}

/// Optional username to scope the eventual `allowCredentials` list by, for
/// non-resident/legacy keys that can't respond to a discoverable challenge.
/// Never encoded in the QR URL — chosen desktop-side, stored server-side on
/// the token row, and only consumed when the phone/browser later hits
/// `/auth/qr-login/authenticate`.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct QrLoginBeginRequest {
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrLoginStatusResponse {
    pub status: QrStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QrLoginAuthenticateRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrLoginAuthenticateResponse {
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
    pub session: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct QrLoginAuthenticateFinishRequest {
    pub token: String,
    pub session: String,
    #[serde(flatten)]
    pub credential: serde_json::Value,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbQrLoginToken {
    pub token: String,
    pub requestee_token: Option<String>,
    pub status: String,
    pub ip_address: Option<String>,
    pub browser_ip_address: Option<String>,
    pub auth_challenge_key: Option<String>,
    pub session_id: Option<String>,
    pub expires_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrSignChallengeRequest {
    pub method: String,
    pub path: String,
    pub body: String,
    pub body_hash: String,
}

// QR Sign types (mid-session signing via phone)

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbQrSignToken {
    pub token: String,
    pub status: String,
    pub challenge_id: String,
    pub challenge_json: String,
    pub method: String,
    pub path: String,
    pub body: String,
    pub body_hash: String,
    pub fido2_response: Option<String>,
    pub ip_address: Option<String>,
    pub browser_ip_address: Option<String>,
    pub expires_at: time::OffsetDateTime,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrSignBeginResponse {
    pub challenge_id: String,
    pub token: String,
    pub url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrSignStatusResponse {
    pub status: QrStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fido2_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QrSignAuthenticateRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrSignAuthenticateResponse {
    #[serde(flatten)]
    pub challenge: webauthn_rs_proto::RequestChallengeResponse,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct QrSignAuthenticateFinishRequest {
    pub token: String,
    #[serde(flatten)]
    pub credential: serde_json::Value,
}

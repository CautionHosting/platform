// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/// Registration state that includes the beta code ID for closed beta
#[derive(Clone)]
pub struct PendingRegistration {
    pub reg_state: SecurityKeyRegistration,
    pub beta_code_id: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub webauthn: Webauthn,
    pub api_service_url: String,
    pub reg_states: Arc<RwLock<HashMap<String, PendingRegistration>>>,
    pub auth_states: Arc<RwLock<HashMap<String, SecurityKeyAuthentication>>>,
    pub sign_challenges: Arc<RwLock<HashMap<String, PendingSignChallenge>>>,
    pub session_timeout_hours: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbUser {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub fido2_user_handle: Option<Vec<u8>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbCredential {
    pub id: i64,
    pub user_id: i64,
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
    pub expires_at: time::PrimitiveDateTime,
    pub created_at: time::PrimitiveDateTime,
    pub last_used_at: time::PrimitiveDateTime,
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
    pub session_id: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginBeginResponse {
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
    pub session: String,
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
    pub session_id: String,
    pub expires_at: String,
    pub credential_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterBeginRequest {
    pub beta_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub passkey_authentication: PasskeyAuthentication,
    pub user_id: i64,
}

#[derive(Debug, Clone)]
pub struct PendingSignChallenge {
    pub auth_state: SecurityKeyAuthentication,
    pub user_id: i64,
    pub method: String,
    pub path: String,
    pub body_hash: String,
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

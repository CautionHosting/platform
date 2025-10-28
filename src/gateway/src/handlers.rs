// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use webauthn_rs::prelude::*;
use time::Duration;
use serde::{Serialize, Deserialize};

use crate::db;
use crate::types::*;

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterBeginResponse {
    #[serde(flatten)]
    pub challenge: CreationChallengeResponse,
    pub session: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishRequestCli {
    #[serde(flatten)]
    pub credential: serde_json::Value,
    pub session: String,
}

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

pub async fn begin_register_handler(
    State(state): State<AppState>,
) -> Result<Json<RegisterBeginResponse>, AppError> {
    tracing::debug!("Registration started");

    let user_unique_id = uuid::Uuid::new_v4();
    let user_name = format!("user_{}", user_unique_id);

    let (ccr, reg_state) = state
        .webauthn
        .start_securitykey_registration(
            user_unique_id,
            &user_name,
            &user_name,
            None,
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Failed to start registration: {}", e))?;

    let state_key = user_unique_id.to_string();
    state.reg_states.write().await.insert(state_key.clone(), reg_state);

    Ok(Json(RegisterBeginResponse {
        challenge: ccr,
        session: state_key,
    }))
}

pub async fn finish_register_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<RegisterFinishResponse>, AppError> {
    let session_key = req.get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing session field"))?
        .to_string();

    let reg_state = state.reg_states.read().await
        .get(&session_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No matching registration state found"))?;

    let reg_response: RegisterPublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse registration response: {}", e))?;

    let passkey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &reg_state)
        .map_err(|e| anyhow::anyhow!("Failed to finish registration: {}", e))?;

    let credential_id = passkey.cred_id().clone();
    if db::credential_exists(&state.db, &credential_id).await? {
        tracing::warn!("Registration rejected - credential already registered");
        return Err(anyhow::anyhow!(
            "This security key is already registered. Each key can only be registered once."
        ).into());
    }

    state.reg_states.write().await.remove(&session_key);

    let user_unique_id = uuid::Uuid::parse_str(&session_key)
        .map_err(|e| anyhow::anyhow!("Failed to parse user ID: {}", e))?;

    let user_id = db::create_user(&state.db, &user_unique_id.as_bytes()[..])
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create user: {}", e))?;

    tracing::debug!("User registered");

    let passkey_json = serde_json::to_vec(&passkey)
        .map_err(|e| anyhow::anyhow!("Failed to serialize passkey: {}", e))?;

    db::save_fido2_credential(
        &state.db,
        &credential_id,
        user_id,
        &passkey_json,
        Some("none"),
        None,
        0,
        None,
        None,
    )
    .await?;

    let credential_id_hex = hex::encode(&credential_id);

    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at).await?;

    tracing::debug!("Registration complete with automatic session creation (expires in {} hours)", state.session_timeout_hours);

    Ok(Json(RegisterFinishResponse {
        status: "success".to_string(),
        credential_id: credential_id_hex,
        session_id: session_id.clone(),
        expires_at: expires_at.to_string(),
    }))
}

pub async fn begin_login_handler(
    State(state): State<AppState>,
) -> Result<Json<LoginBeginResponse>, AppError> {
    tracing::debug!("Creating authentication challenge with allow-credentials (UV=preferred)");

    let all_credential_ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT credential_id FROM fido2_credentials"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to fetch credentials: {}", e))?;

    let mut allow_credentials = Vec::new();
    for cred_id_bytes in all_credential_ids {
        let cred_bytes = db::get_credential_public_key(&state.db, &cred_id_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get credential: {}", e))?;
        let security_key: SecurityKey = serde_json::from_slice(&cred_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize credential: {}", e))?;
        allow_credentials.push(security_key);
    }

    tracing::debug!("Found {} credentials for authentication", allow_credentials.len());

    let (rcr, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&allow_credentials)
        .map_err(|e| anyhow::anyhow!("Failed to start authentication: {}", e))?;

    let session_key = uuid::Uuid::new_v4().to_string();
    state.auth_states.write().await.insert(session_key.clone(), auth_state);

    Ok(Json(LoginBeginResponse {
        challenge: rcr,
        session: session_key,
    }))
}

pub async fn finish_login_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<LoginFinishResponse>, AppError> {
    let session_key = req.get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing session field"))?
        .to_string();

    let auth_state = state.auth_states.read().await
        .get(&session_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired session key"))?;

    let auth_response: PublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse auth response: {}", e))?;

    tracing::debug!("Received authentication response");

    let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
    tracing::debug!("Credential ID: {}", hex::encode(&credential_id_bytes));

    let _user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes).await?;

    let passkey_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes).await?;
    let mut passkey: Passkey = serde_json::from_slice(&passkey_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize passkey: {}", e))?;

    tracing::debug!("Credential fetched, performing security key authentication");

    let auth_result = state
        .webauthn
        .finish_securitykey_authentication(&auth_response, &auth_state)
        .map_err(|e| {
            tracing::error!("Authentication failed: {:?}", e);
            anyhow::anyhow!("Failed to finish authentication: {}", e)
        })?;

    tracing::debug!("Authentication successful");

    if auth_result.needs_update() {
        let update_result = passkey.update_credential(&auth_result);

        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&passkey)
                .map_err(|e| anyhow::anyhow!("Failed to serialize updated passkey: {}", e))?;

            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await?;
        }
    }

    state.auth_states.write().await.remove(&session_key);

    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at).await?;

    let credential_id_hex = hex::encode(&credential_id_bytes);
    tracing::debug!("Login complete (session expires in {} hours)", state.session_timeout_hours);

    Ok(Json(LoginFinishResponse {
        session_id: session_id.clone(),
        expires_at: expires_at.to_string(),
        credential_id: credential_id_hex,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AddSshKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddSshKeyResponse {
    pub id: i64,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct ListSshKeysResponse {
    pub keys: Vec<crate::db::SshKeyInfo>,
}

pub async fn add_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Json(req): Json<AddSshKeyRequest>,
) -> Result<Json<AddSshKeyResponse>, AppError> {
    let user_id: i64 = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    crate::validation::validate_ssh_public_key(&req.public_key)
        .map_err(|e| anyhow::anyhow!("Invalid SSH public key: {}", e))?;

    let key_type = req.public_key.trim().split_whitespace().next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse key type"))?;

    let key_id = crate::db::add_ssh_key(
        &state.db,
        user_id,
        &req.public_key,
        key_type,
        req.name.as_deref(),
    )
    .await?;

    let fingerprint = crate::db::generate_ssh_fingerprint(&req.public_key);

    tracing::debug!("SSH key added");
    
    Ok(Json(AddSshKeyResponse {
        id: key_id,
        fingerprint,
    }))
}

pub async fn list_ssh_keys_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
) -> Result<Json<ListSshKeysResponse>, AppError> {
    let user_id: i64 = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;
    
    let keys = crate::db::list_ssh_keys(&state.db, user_id).await?;
    
    Ok(Json(ListSshKeysResponse { keys }))
}

pub async fn delete_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Path(fingerprint): Path<String>,
) -> Result<StatusCode, AppError> {
    let user_id: i64 = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    let deleted = crate::db::delete_ssh_key(&state.db, user_id, &fingerprint).await?;

    if deleted {
        tracing::debug!("SSH key deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(anyhow::anyhow!("SSH key not found").into())
    }
}

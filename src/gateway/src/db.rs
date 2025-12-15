// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use sqlx::PgPool;
use rand::Rng;
use time::{OffsetDateTime, PrimitiveDateTime};
use base64::Engine;

use crate::types::DbSession;

pub async fn create_user(pool: &PgPool, fido2_user_handle: &[u8], beta_code_id: i64) -> Result<i64> {
    let username = generate_user_identifier();

    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (fido2_user_handle, username, email, beta_code_id)
         VALUES ($1, $2, NULL, $3)
         RETURNING id"
    )
    .bind(fido2_user_handle)
    .bind(&username)
    .bind(beta_code_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error creating user: {:?}", e);
        tracing::error!("Username attempted: {}", username);
        tracing::error!("fido2_user_handle (hex): {}", hex::encode(fido2_user_handle));
        anyhow::anyhow!("Failed to create user: {}", e)
    })?;

    Ok(user_id)
}

pub async fn validate_beta_code(pool: &PgPool, code: &str) -> Result<Option<i64>> {
    let code_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM beta_codes
         WHERE code = $1
           AND used_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())"
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .context("Failed to validate beta code")?;

    Ok(code_id)
}

pub async fn redeem_beta_code(pool: &PgPool, code_id: i64) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE beta_codes
         SET used_at = NOW()
         WHERE id = $1
           AND used_at IS NULL"
    )
    .bind(code_id)
    .execute(pool)
    .await
    .context("Failed to redeem beta code")?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_user_id_by_fido2_handle(pool: &PgPool, fido2_user_handle: &[u8]) -> Result<i64> {
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE fido2_user_handle = $1"
    )
    .bind(fido2_user_handle)
    .fetch_optional(pool)
    .await
    .context("Failed to get user ID")?;
    
    user_id.ok_or_else(|| anyhow::anyhow!("User not found for handle"))
}

fn generate_user_identifier() -> String {
    let random_bytes: [u8; 16] = rand::thread_rng().gen();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);
    format!("u_{}", encoded)
}

pub async fn save_fido2_credential(
    pool: &PgPool,
    credential_id: &[u8],
    user_id: i64,
    public_key: &[u8],
    attestation_type: Option<&str>,
    aaguid: Option<&[u8]>,
    sign_count: u32,
    transport: Option<serde_json::Value>,
    flags: Option<serde_json::Value>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO fido2_credentials (
            credential_id,
            user_id,
            public_key,
            attestation_type,
            aaguid,
            sign_count,
            transport,
            flags,
            created_at,
            updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())"
    )
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(attestation_type)
    .bind(aaguid)
    .bind(sign_count as i64)
    .bind(transport)
    .bind(flags)
    .execute(pool)
    .await
    .context("Failed to save credential")?;
    
    Ok(())
}

pub async fn credential_exists(pool: &PgPool, credential_id: &[u8]) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM fido2_credentials WHERE credential_id = $1)"
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .context("Failed to check credential existence")?;
    
    Ok(exists)
}

pub async fn get_credential_public_key(pool: &PgPool, credential_id: &[u8]) -> Result<Vec<u8>> {
    let public_key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT public_key FROM fido2_credentials WHERE credential_id = $1"
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .context("Failed to get credential")?;
    
    public_key.ok_or_else(|| anyhow::anyhow!("Credential not found"))
}

pub async fn get_user_id_by_credential(pool: &PgPool, credential_id: &[u8]) -> Result<i64> {
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM fido2_credentials WHERE credential_id = $1"
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .context("Failed to get user ID")?;
    
    user_id.ok_or_else(|| anyhow::anyhow!("Credential not found"))
}

pub async fn get_all_credential_ids(pool: &PgPool) -> Result<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT credential_id FROM fido2_credentials ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await
    .context("Failed to query credentials")?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_all_passkeys(pool: &PgPool) -> Result<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT public_key FROM fido2_credentials ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await
    .context("Failed to query passkeys")?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn get_credential_ids_by_user_id(pool: &PgPool, user_id: i64) -> Result<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT credential_id FROM fido2_credentials WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("Failed to query credentials")?;
    
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn update_sign_count(pool: &PgPool, credential_id: &[u8], sign_count: u32) -> Result<()> {
    sqlx::query(
        "UPDATE fido2_credentials SET sign_count = $1, updated_at = NOW() WHERE credential_id = $2"
    )
    .bind(sign_count as i64)
    .bind(credential_id)
    .execute(pool)
    .await
    .context("Failed to update sign count")?;
    
    Ok(())
}

pub async fn update_fido2_credential(
    pool: &PgPool,
    credential_id: &[u8],
    public_key: &[u8],
    sign_count: u32,
) -> Result<()> {
    sqlx::query(
        "UPDATE fido2_credentials 
         SET public_key = $1, sign_count = $2, updated_at = NOW() 
         WHERE credential_id = $3"
    )
    .bind(public_key)
    .bind(sign_count as i64)
    .bind(credential_id)
    .execute(pool)
    .await
    .context("Failed to update credential")?;
    
    Ok(())
}

pub async fn create_auth_session(
    pool: &PgPool,
    session_id: &str,
    credential_id: &[u8],
    expires_at: OffsetDateTime,
) -> Result<()> {
    let expires_at_primitive = PrimitiveDateTime::new(expires_at.date(), expires_at.time());

    sqlx::query(
        "INSERT INTO auth_sessions (session_id, credential_id, created_at, expires_at, last_used_at)
         VALUES ($1, $2, NOW(), $3, NOW())"
    )
    .bind(session_id)
    .bind(credential_id)
    .bind(expires_at_primitive)
    .execute(pool)
    .await
    .context("Failed to create session")?;

    Ok(())
}

pub async fn validate_auth_session(pool: &PgPool, session_id: &str) -> Result<Option<Vec<u8>>> {
    let session: Option<DbSession> = sqlx::query_as(
        "SELECT session_id, credential_id, expires_at, created_at, last_used_at
         FROM auth_sessions
         WHERE session_id = $1"
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .context("Failed to validate session")?;

    let Some(session) = session else {
        return Ok(None);
    };

    let now_utc = OffsetDateTime::now_utc();
    let now_primitive = PrimitiveDateTime::new(now_utc.date(), now_utc.time());

    if now_primitive > session.expires_at {
        return Ok(None);
    }

    let _ = sqlx::query(
        "UPDATE auth_sessions SET last_used_at = NOW() WHERE session_id = $1"
    )
    .bind(session_id)
    .execute(pool)
    .await;

    Ok(Some(session.credential_id))
}

pub async fn delete_auth_session(pool: &PgPool, session_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM auth_sessions WHERE session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .context("Failed to delete session")?;
    
    Ok(())
}

pub async fn cleanup_expired_sessions(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM auth_sessions WHERE expires_at < NOW()")
        .execute(pool)
        .await
        .context("Failed to cleanup sessions")?;
    
    Ok(result.rows_affected())
}

pub fn generate_session_id() -> String {
    let random_bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
}

use sha2::{Sha256, Digest};

pub async fn add_ssh_key(
    pool: &PgPool,
    user_id: i64,
    public_key: &str,
    key_type: &str,
    name: Option<&str>,
) -> Result<i64> {
    let fingerprint = generate_ssh_fingerprint(public_key);

    let key_id: i64 = sqlx::query_scalar(
        "INSERT INTO ssh_keys (user_id, public_key, fingerprint, key_type, name)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id"
    )
    .bind(user_id)
    .bind(public_key)
    .bind(&fingerprint)
    .bind(key_type)
    .bind(name)
    .fetch_one(pool)
    .await
    .context("Failed to insert SSH key")?;

    Ok(key_id)
}

pub async fn get_user_by_ssh_key(pool: &PgPool, public_key: &str) -> Result<Option<i64>> {
    let fingerprint = generate_ssh_fingerprint(public_key);
    
    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM ssh_keys WHERE fingerprint = $1"
    )
    .bind(&fingerprint)
    .fetch_optional(pool)
    .await
    .context("Failed to get user by SSH key")?;
    
    Ok(user_id)
}

pub async fn list_ssh_keys(pool: &PgPool, user_id: i64) -> Result<Vec<SshKeyInfo>> {
    let keys: Vec<SshKeyInfo> = sqlx::query_as(
        "SELECT id, fingerprint, key_type, name, created_at 
         FROM ssh_keys 
         WHERE user_id = $1 
         ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("Failed to list SSH keys")?;
    
    Ok(keys)
}

pub async fn delete_ssh_key(pool: &PgPool, user_id: i64, fingerprint: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM ssh_keys WHERE user_id = $1 AND fingerprint = $2"
    )
    .bind(user_id)
    .bind(fingerprint)
    .execute(pool)
    .await
    .context("Failed to delete SSH key")?;
    
    Ok(result.rows_affected() > 0)
}

pub fn generate_ssh_fingerprint(public_key: &str) -> String {
    let parts: Vec<&str> = public_key.split_whitespace().collect();
    let key_data = if parts.len() >= 2 {
        parts[1]
    } else {
        public_key.trim()
    };
    
    let mut hasher = Sha256::new();
    hasher.update(key_data.as_bytes());
    let result = hasher.finalize();
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(result))
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SshKeyInfo {
    pub id: i64,
    pub fingerprint: String,
    pub key_type: String,
    pub name: Option<String>,
    pub created_at: time::PrimitiveDateTime,
}


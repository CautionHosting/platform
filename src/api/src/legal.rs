// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext};

#[derive(Debug, Serialize)]
pub struct LegalDocumentStatus {
    pub active_version: Option<String>,
    pub latest_user_version: Option<String>,
    pub requires_action: bool,
}

#[derive(Debug, Serialize)]
pub struct UserLegalStatus {
    pub terms_of_service: LegalDocumentStatus,
    pub privacy_notice: LegalDocumentStatus,
}

/// Get the active version for a document type, or None if no active version exists.
async fn get_active_version(pool: &PgPool, document_type: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT version FROM legal_documents
         WHERE document_type = $1 AND is_active = true"
    )
    .bind(document_type)
    .fetch_optional(pool)
    .await
}

/// Get the latest version a user accepted/acknowledged for a document type.
/// For terms_of_service, looks for 'accepted' events.
/// For privacy_notice, looks for 'acknowledged' events.
async fn get_latest_user_version(
    pool: &PgPool,
    user_id: Uuid,
    document_type: &str,
    event_type: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT document_version FROM user_legal_events
         WHERE user_id = $1
           AND document_type = $2
           AND event_type = $3
         ORDER BY occurred_at DESC
         LIMIT 1"
    )
    .bind(user_id)
    .bind(document_type)
    .bind(event_type)
    .fetch_optional(pool)
    .await
}

/// Compute legal status for a single document type.
fn compute_document_status(
    active_version: Option<String>,
    latest_user_version: Option<String>,
) -> LegalDocumentStatus {
    let requires_action = match (&active_version, &latest_user_version) {
        // Active version exists, user has a record: compare versions
        (Some(active), Some(user_ver)) => active != user_ver,
        // Active version exists, user has no record: user predates tracking,
        // do not retroactively gate
        (Some(_), None) => false,
        // No active version: nothing to enforce
        (None, _) => false,
    };

    LegalDocumentStatus {
        active_version,
        latest_user_version,
        requires_action,
    }
}

/// Get the full legal status for a user across all document types.
pub async fn get_user_legal_status(pool: &PgPool, user_id: Uuid) -> Result<UserLegalStatus, sqlx::Error> {
    let tos_active = get_active_version(pool, "terms_of_service").await?;
    let pn_active = get_active_version(pool, "privacy_notice").await?;

    let tos_user = get_latest_user_version(pool, user_id, "terms_of_service", "accepted").await?;
    let pn_user = get_latest_user_version(pool, user_id, "privacy_notice", "acknowledged").await?;

    Ok(UserLegalStatus {
        terms_of_service: compute_document_status(tos_active, tos_user),
        privacy_notice: compute_document_status(pn_active, pn_user),
    })
}

#[derive(Debug, Deserialize)]
pub struct AcceptLegalRequest {
    pub document_type: String,
}

#[derive(Debug, Serialize)]
pub struct AcceptLegalResponse {
    pub success: bool,
    pub document_type: String,
    pub version: String,
    pub event_type: String,
    pub legal: UserLegalStatus,
}

/// Accept/acknowledge the current active version of a legal document.
/// Records an append-only event and returns the updated legal status.
pub async fn accept_legal_document(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(payload): Json<AcceptLegalRequest>,
) -> Result<Json<AcceptLegalResponse>, (StatusCode, String)> {
    let event_type = match payload.document_type.as_str() {
        "terms_of_service" => "accepted",
        "privacy_notice" => "acknowledged",
        _ => return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid document_type: '{}'. Must be 'terms_of_service' or 'privacy_notice'", payload.document_type),
        )),
    };

    let active_version: Option<String> = get_active_version(&state.db, &payload.document_type)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get active legal version: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to query legal documents".to_string())
        })?;

    let version = active_version.ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("No active {} document found", payload.document_type))
    })?;

    let session_id = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    sqlx::query(
        "INSERT INTO user_legal_events (
            user_id, document_type, document_version,
            event_type, event_source, occurred_at, session_id
        ) VALUES ($1, $2, $3, $4, $5, NOW(), $6)"
    )
    .bind(auth.user_id)
    .bind(&payload.document_type)
    .bind(&version)
    .bind(event_type)
    .bind("login_gate")
    .bind(session_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to record legal event: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to record legal acceptance".to_string())
    })?;

    tracing::info!(
        "User {} {} {} version {}",
        auth.user_id, event_type, payload.document_type, version
    );

    let legal = get_user_legal_status(&state.db, auth.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch updated legal status: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch legal status".to_string())
        })?;

    Ok(Json(AcceptLegalResponse {
        success: true,
        document_type: payload.document_type,
        version,
        event_type: event_type.to_string(),
        legal,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_user_requires_no_action() {
        let status = compute_document_status(
            Some("2026-04-08".to_string()),
            Some("2026-04-08".to_string()),
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.latest_user_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_outdated_user_requires_action() {
        let status = compute_document_status(
            Some("2026-06-01".to_string()),
            Some("2026-04-08".to_string()),
        );
        assert!(status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-06-01"));
        assert_eq!(status.latest_user_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_pre_tracking_user_no_action() {
        // User has no legal event rows (predates tracking)
        let status = compute_document_status(
            Some("2026-04-08".to_string()),
            None,
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.latest_user_version, None);
    }

    #[test]
    fn test_no_active_version_no_action() {
        let status = compute_document_status(None, None);
        assert!(!status.requires_action);
        assert_eq!(status.active_version, None);
    }

    #[test]
    fn test_no_active_version_with_user_event_no_action() {
        // Edge case: user accepted a version that's since been deactivated
        // with no replacement. Should not require action.
        let status = compute_document_status(
            None,
            Some("2026-04-08".to_string()),
        );
        assert!(!status.requires_action);
    }
}

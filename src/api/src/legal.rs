// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{AppState, AuthContext};

#[derive(Debug, Clone, FromRow)]
struct LegalDocumentIdentity {
    id: Uuid,
    version: String,
    source_commit_sha: Option<String>,
    source_path: Option<String>,
    occurred_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct LegalDocumentStatus {
    pub active_version: Option<String>,
    pub latest_user_version: Option<String>,
    pub latest_user_accepted_at: Option<DateTime<Utc>>,
    pub requires_action: bool,
    pub source_commit_sha: Option<String>,
    pub source_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserLegalStatus {
    pub terms_of_service: LegalDocumentStatus,
    pub privacy_notice: LegalDocumentStatus,
}

fn expected_event_type(document_type: &str) -> Option<&'static str> {
    match document_type {
        "terms_of_service" => Some("accepted"),
        "privacy_notice" => Some("acknowledged"),
        _ => None,
    }
}

/// Get the active version for a document type, or None if no active version exists.
async fn get_active_document(
    pool: &PgPool,
    document_type: &str,
) -> Result<Option<LegalDocumentIdentity>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, version, source_commit_sha, source_path, NULL::timestamptz AS occurred_at FROM legal_documents
         WHERE document_type = $1 AND is_active = true"
    )
    .bind(document_type)
    .fetch_optional(pool)
    .await
}

/// Get the latest version a user accepted/acknowledged for a document type.
/// For terms_of_service, looks for 'accepted' events.
/// For privacy_notice, looks for 'acknowledged' events.
async fn get_latest_user_document(
    pool: &PgPool,
    user_id: Uuid,
    document_type: &str,
    event_type: &str,
) -> Result<Option<LegalDocumentIdentity>, sqlx::Error> {
    sqlx::query_as(
        "SELECT
            legal_document_id AS id,
            document_version AS version,
            NULL::TEXT AS source_commit_sha,
            NULL::TEXT AS source_path,
            occurred_at
         FROM user_legal_events
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
    active_document: Option<LegalDocumentIdentity>,
    latest_user_document: Option<LegalDocumentIdentity>,
) -> LegalDocumentStatus {
    let active_version = active_document.as_ref().map(|doc| doc.version.clone());
    let latest_user_version = latest_user_document.as_ref().map(|doc| doc.version.clone());
    let latest_user_accepted_at = latest_user_document.as_ref().and_then(|doc| doc.occurred_at);
    let source_commit_sha = active_document.as_ref().and_then(|doc| doc.source_commit_sha.clone());
    let source_path = active_document.as_ref().and_then(|doc| doc.source_path.clone());

    let requires_action = match (&active_document, &latest_user_document) {
        // Compare exact legal document rows, not just display versions.
        (Some(active), Some(user_doc)) => active.id != user_doc.id,
        // Active version exists, user has no record: user predates tracking,
        // do not retroactively gate
        (Some(_), None) => false,
        // No active version: nothing to enforce
        (None, _) => false,
    };

    LegalDocumentStatus {
        active_version,
        latest_user_version,
        latest_user_accepted_at,
        requires_action,
        source_commit_sha,
        source_path,
    }
}

/// Get the full legal status for a user across all document types.
pub async fn get_user_legal_status(pool: &PgPool, user_id: Uuid) -> Result<UserLegalStatus, sqlx::Error> {
    let tos_active = get_active_document(pool, "terms_of_service").await?;
    let pn_active = get_active_document(pool, "privacy_notice").await?;

    let tos_user = get_latest_user_document(pool, user_id, "terms_of_service", "accepted").await?;
    let pn_user = get_latest_user_document(pool, user_id, "privacy_notice", "acknowledged").await?;

    Ok(UserLegalStatus {
        terms_of_service: compute_document_status(tos_active, tos_user),
        privacy_notice: compute_document_status(pn_active, pn_user),
    })
}

pub async fn get_blocking_document_requiring_acceptance(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let blocking_document_types: Vec<String> = sqlx::query_scalar(
        "SELECT document_type
         FROM legal_documents
         WHERE is_active = true
           AND requires_blocking_reacceptance = true
         ORDER BY CASE document_type
            WHEN 'terms_of_service' THEN 0
            WHEN 'privacy_notice' THEN 1
            ELSE 2
         END"
    )
    .fetch_all(pool)
    .await?;

    for document_type in blocking_document_types {
        let Some(event_type) = expected_event_type(&document_type) else {
            continue;
        };

        let active_document = get_active_document(pool, &document_type).await?;
        let latest_user_document =
            get_latest_user_document(pool, user_id, &document_type, event_type).await?;

        if compute_document_status(active_document, latest_user_document).requires_action {
            return Ok(Some(document_type));
        }
    }

    Ok(None)
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
    let event_type = expected_event_type(payload.document_type.as_str()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid document_type: '{}'. Must be 'terms_of_service' or 'privacy_notice'",
                payload.document_type
            ),
        )
    })?;

    let active_document = get_active_document(&state.db, &payload.document_type)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get active legal version: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to query legal documents".to_string())
        })?;

    let active_document = active_document.ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("No active {} document found", payload.document_type))
    })?;
    let version = active_document.version.clone();

    let session_id = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    sqlx::query(
        "INSERT INTO user_legal_events (
            user_id, legal_document_id, document_type, document_version,
            event_type, event_source, occurred_at, session_id
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)"
    )
    .bind(auth.user_id)
    .bind(active_document.id)
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
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.latest_user_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_outdated_user_requires_action() {
        let status = compute_document_status(
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                version: "2026-06-01".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
        );
        assert!(status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-06-01"));
        assert_eq!(status.latest_user_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_pre_tracking_user_no_action() {
        // User has no legal event rows (predates tracking)
        let status = compute_document_status(
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
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
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                source_commit_sha: None,
                source_path: None,
                occurred_at: None,
            }),
        );
        assert!(!status.requires_action);
    }
}

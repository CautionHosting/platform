// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use uuid::Uuid;

use crate::{validation::validate_email, AppState, AuthContext};

#[derive(Debug, Clone, FromRow)]
struct LegalDocumentIdentity {
    id: Uuid,
    version: String,
    occurred_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
struct LegalNoticeDocument {
    id: Uuid,
    document_type: String,
    version: String,
    url: String,
    effective_at: DateTime<Utc>,
    requires_blocking_reacceptance: bool,
    requires_acknowledgment: bool,
}

#[derive(Debug, Clone, FromRow)]
struct LegalNoticeRecipient {
    id: Uuid,
    email: String,
}

#[derive(Debug, Serialize)]
pub struct LegalDocumentStatus {
    pub active_version: Option<String>,
    pub accepted_version: Option<String>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub requires_action: bool,
}

#[derive(Debug, Serialize)]
pub struct UserLegalStatus {
    pub terms_of_service: LegalDocumentStatus,
    pub privacy_notice: LegalDocumentStatus,
}

#[derive(Debug, Deserialize)]
pub struct SendLegalNoticesRequest {
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub document_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub recipient_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub recipient_emails: Option<Vec<String>>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LegalNoticeDocumentResponse {
    pub id: Uuid,
    pub document_type: String,
    pub title: String,
    pub version: String,
    pub url: String,
    pub effective_at: DateTime<Utc>,
    pub requires_action: bool,
}

#[derive(Debug, Serialize)]
pub struct SendLegalNoticesResponse {
    pub dry_run: bool,
    pub batch_id: Option<Uuid>,
    pub documents: Vec<LegalNoticeDocumentResponse>,
    pub eligible_recipient_count: i64,
    pub already_sent_count: i64,
    pub pending_recipient_count: i64,
    pub selected_recipient_count: i64,
    pub sent_count: i64,
    pub failed_count: i64,
    pub has_more: bool,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct EmailServiceResponse {
    success: bool,
    message: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct RecipientSelection {
    recipient_ids: Option<Vec<Uuid>>,
    recipient_emails: Option<Vec<String>>,
    limit: Option<i64>,
}

impl RecipientSelection {
    fn from_request(
        request: &SendLegalNoticesRequest,
    ) -> Result<Self, (StatusCode, String)> {
        let recipient_ids = match request.recipient_ids.as_ref() {
            Some(ids) if ids.is_empty() => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "recipient_ids must not be empty".to_string(),
                ));
            }
            Some(ids) => Some(ids.clone()),
            None => None,
        };

        let recipient_emails = match request.recipient_emails.as_ref() {
            Some(emails) if emails.is_empty() => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "recipient_emails must not be empty".to_string(),
                ));
            }
            Some(emails) => {
                let mut normalized = Vec::with_capacity(emails.len());
                for email in emails {
                    let trimmed = email.trim().to_lowercase();
                    if trimmed.is_empty() {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            "recipient_emails must not contain empty values".to_string(),
                        ));
                    }
                    validate_email(&trimmed).map_err(|e| {
                        (
                            StatusCode::BAD_REQUEST,
                            format!("Invalid recipient email '{}': {}", email, e),
                        )
                    })?;
                    normalized.push(trimmed);
                }
                normalized.sort_unstable();
                normalized.dedup();
                Some(normalized)
            }
            None => None,
        };

        let limit = match request.limit {
            Some(0) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "limit must be greater than zero".to_string(),
                ));
            }
            Some(limit) => Some(i64::from(limit)),
            None => None,
        };

        Ok(Self {
            recipient_ids,
            recipient_emails,
            limit,
        })
    }

    fn limit_or_max(&self) -> i64 {
        self.limit.unwrap_or(i64::MAX)
    }
}

fn expected_event_type(document_type: &str) -> Option<&'static str> {
    match document_type {
        "terms_of_service" => Some("accepted"),
        "privacy_notice" => Some("acknowledged"),
        _ => None,
    }
}

fn legal_document_title(document_type: &str) -> &'static str {
    match document_type {
        "terms_of_service" => "Terms of Service",
        "privacy_notice" => "Privacy Notice",
        _ => "Legal Document",
    }
}

fn legal_notice_dedupe_key(
    terms_document_id: Option<Uuid>,
    privacy_document_id: Option<Uuid>,
) -> String {
    format!(
        "terms={};privacy={}",
        terms_document_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_string()),
        privacy_document_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_string())
    )
}

/// Get the active version for a document type, or None if no active version exists.
async fn get_active_document(
    pool: &PgPool,
    document_type: &str,
) -> Result<Option<LegalDocumentIdentity>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, version, NULL::timestamptz AS occurred_at FROM legal_documents
         WHERE document_type = $1 AND is_active = true",
    )
    .bind(document_type)
    .fetch_optional(pool)
    .await
}

/// Get the user's most recent accepted/acknowledged document for a document type.
/// This is derived from append-only user_legal_events by document_type + event_type,
/// ordered by occurred_at descending.
async fn get_latest_user_document_by_type(
    pool: &PgPool,
    user_id: Uuid,
    document_type: &str,
    event_type: &str,
) -> Result<Option<LegalDocumentIdentity>, sqlx::Error> {
    sqlx::query_as(
        "SELECT
            legal_document_id AS id,
            document_version AS version,
            occurred_at
         FROM user_legal_events
         WHERE user_id = $1
           AND document_type = $2
           AND event_type = $3
         ORDER BY occurred_at DESC
         LIMIT 1",
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
    let accepted_version = latest_user_document.as_ref().map(|doc| doc.version.clone());
    let accepted_at = latest_user_document
        .as_ref()
        .and_then(|doc| doc.occurred_at);

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
        accepted_version,
        accepted_at,
        requires_action,
    }
}

/// Get the full legal status for a user across all document types.
pub async fn get_user_legal_status(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserLegalStatus, sqlx::Error> {
    let tos_active = get_active_document(pool, "terms_of_service").await?;
    let pn_active = get_active_document(pool, "privacy_notice").await?;

    let tos_user =
        get_latest_user_document_by_type(pool, user_id, "terms_of_service", "accepted").await?;
    let pn_user =
        get_latest_user_document_by_type(pool, user_id, "privacy_notice", "acknowledged").await?;

    Ok(UserLegalStatus {
        terms_of_service: compute_document_status(tos_active, tos_user),
        privacy_notice: compute_document_status(pn_active, pn_user),
    })
}

pub async fn get_blocking_document_requiring_acceptance(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let legal = get_user_legal_status(pool, user_id).await?;

    let tos_blocking: bool = sqlx::query_scalar(
        "SELECT COALESCE(MAX(requires_blocking_reacceptance::int), 0)::bool
         FROM legal_documents
         WHERE document_type = 'terms_of_service'
           AND is_active = true",
    )
    .fetch_one(pool)
    .await?;

    if tos_blocking && legal.terms_of_service.requires_action {
        return Ok(Some("terms_of_service".to_string()));
    }

    let pn_blocking: bool = sqlx::query_scalar(
        "SELECT COALESCE(MAX(requires_blocking_reacceptance::int), 0)::bool
         FROM legal_documents
         WHERE document_type = 'privacy_notice'
           AND is_active = true",
    )
    .fetch_one(pool)
    .await?;

    if pn_blocking && legal.privacy_notice.requires_action {
        return Ok(Some("privacy_notice".to_string()));
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to query legal documents".to_string(),
            )
        })?;

    let active_document = active_document.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("No active {} document found", payload.document_type),
        )
    })?;
    let version = active_document.version.clone();

    let session_id = headers.get("x-session-id").and_then(|v| v.to_str().ok());

    sqlx::query(
        "INSERT INTO user_legal_events (
            user_id, legal_document_id, document_type, document_version,
            event_type, event_source, occurred_at, session_id
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)",
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to record legal acceptance".to_string(),
        )
    })?;

    tracing::info!(
        "User {} {} {} version {}",
        auth.user_id,
        event_type,
        payload.document_type,
        version
    );

    let legal = get_user_legal_status(&state.db, auth.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch updated legal status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch legal status".to_string(),
            )
        })?;

    Ok(Json(AcceptLegalResponse {
        success: true,
        document_type: payload.document_type,
        version,
        event_type: event_type.to_string(),
        legal,
    }))
}

pub async fn send_legal_notices(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendLegalNoticesRequest>,
) -> Result<Json<SendLegalNoticesResponse>, (StatusCode, String)> {
    let recipient_selection = RecipientSelection::from_request(&payload)?;
    let documents = load_legal_notice_documents(&state.db, payload.document_ids.as_deref()).await?;
    let (terms_document_id, privacy_document_id) = legal_notice_document_ids(&documents)?;
    let dedupe_key = legal_notice_dedupe_key(terms_document_id, privacy_document_id);

    let existing_batch_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM legal_notice_batches WHERE dedupe_key = $1")
            .bind(&dedupe_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to query legal notice batch: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to query legal notice batch".to_string(),
                )
            })?;

    let dry_run_batch_id = existing_batch_id;
    let batch_id = if payload.dry_run {
        dry_run_batch_id
    } else {
        Some(
            upsert_legal_notice_batch(
                &state.db,
                &dedupe_key,
                terms_document_id,
                privacy_document_id,
            )
            .await?,
        )
    };

    let eligible_recipient_count =
        count_legal_notice_recipients(&state.db, &recipient_selection).await?;
    let already_sent_count = count_sent_legal_notice_deliveries(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await?;
    let pending_recipient_count = count_pending_legal_notice_recipients(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await?;
    let recipients = load_pending_legal_notice_recipients(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await?;
    let selected_recipient_count = recipients.len() as i64;
    let has_more = pending_recipient_count > selected_recipient_count;

    let response_documents = documents
        .iter()
        .map(|doc| LegalNoticeDocumentResponse {
            id: doc.id,
            document_type: doc.document_type.clone(),
            title: legal_document_title(&doc.document_type).to_string(),
            version: doc.version.clone(),
            url: doc.url.clone(),
            effective_at: doc.effective_at.clone(),
            requires_action: doc.requires_blocking_reacceptance || doc.requires_acknowledgment,
        })
        .collect();

    if payload.dry_run {
        return Ok(Json(SendLegalNoticesResponse {
            dry_run: true,
            batch_id,
            documents: response_documents,
            eligible_recipient_count,
            already_sent_count,
            pending_recipient_count,
            selected_recipient_count,
            sent_count: 0,
            failed_count: 0,
            has_more,
            limit: recipient_selection.limit,
        }));
    }

    let batch_id = batch_id.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create legal notice batch".to_string(),
        )
    })?;

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let email_data = build_legal_notice_email_data(&documents);
    let mut sent_count = 0;
    let mut failed_count = 0;

    for recipient in recipients {
        let email_request = serde_json::json!({
            "to": &recipient.email,
            "template": "legal_notice",
            "data": email_data.clone(),
        });

        let delivery_result = send_legal_notice_email(&client, &email_service_url, &email_request)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to send legal notice email to user {}: {}",
                    recipient.id,
                    e
                );
                e
            });

        match delivery_result {
            Ok(()) => {
                sent_count += 1;
                record_legal_notice_delivery(
                    &state.db,
                    batch_id,
                    recipient.id,
                    &recipient.email,
                    "sent",
                    None,
                )
                .await?;
            }
            Err(e) => {
                failed_count += 1;
                record_legal_notice_delivery(
                    &state.db,
                    batch_id,
                    recipient.id,
                    &recipient.email,
                    "failed",
                    Some(&e),
                )
                .await?;
            }
        }
    }

    Ok(Json(SendLegalNoticesResponse {
        dry_run: false,
        batch_id: Some(batch_id),
        documents: response_documents,
        eligible_recipient_count,
        already_sent_count,
        pending_recipient_count,
        selected_recipient_count,
        sent_count,
        failed_count,
        has_more,
        limit: recipient_selection.limit,
    }))
}

async fn load_legal_notice_documents(
    pool: &PgPool,
    document_ids: Option<&[Uuid]>,
) -> Result<Vec<LegalNoticeDocument>, (StatusCode, String)> {
    let documents = if let Some(document_ids) = document_ids {
        if document_ids.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "document_ids must not be empty".to_string(),
            ));
        }

        sqlx::query_as::<_, LegalNoticeDocument>(
            "SELECT id,
                    document_type,
                    version,
                    url,
                    effective_at,
                    requires_blocking_reacceptance,
                    requires_acknowledgment
             FROM legal_documents
             WHERE id = ANY($1)
             ORDER BY CASE document_type
                 WHEN 'terms_of_service' THEN 1
                 WHEN 'privacy_notice' THEN 2
                 ELSE 3
             END",
        )
        .bind(document_ids)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, LegalNoticeDocument>(
            "SELECT id,
                    document_type,
                    version,
                    url,
                    effective_at,
                    requires_blocking_reacceptance,
                    requires_acknowledgment
             FROM legal_documents
             WHERE is_active = true
               AND document_type IN ('terms_of_service', 'privacy_notice')
             ORDER BY CASE document_type
                 WHEN 'terms_of_service' THEN 1
                 WHEN 'privacy_notice' THEN 2
                 ELSE 3
             END",
        )
        .fetch_all(pool)
        .await
    }
    .map_err(|e| {
        tracing::error!("Failed to load legal notice documents: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load legal notice documents".to_string(),
        )
    })?;

    if documents.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No legal documents selected for notice".to_string(),
        ));
    }

    if let Some(document_ids) = document_ids {
        if documents.len() != document_ids.len() {
            return Err((
                StatusCode::BAD_REQUEST,
                "One or more document_ids were not found".to_string(),
            ));
        }
    }

    Ok(documents)
}

fn legal_notice_document_ids(
    documents: &[LegalNoticeDocument],
) -> Result<(Option<Uuid>, Option<Uuid>), (StatusCode, String)> {
    let mut terms_document_id = None;
    let mut privacy_document_id = None;

    for document in documents {
        match document.document_type.as_str() {
            "terms_of_service" if terms_document_id.is_none() => {
                terms_document_id = Some(document.id);
            }
            "privacy_notice" if privacy_document_id.is_none() => {
                privacy_document_id = Some(document.id);
            }
            "terms_of_service" | "privacy_notice" => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Legal notice batches can include at most one document of each type"
                        .to_string(),
                ));
            }
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Unsupported legal document type: {}",
                        document.document_type
                    ),
                ));
            }
        }
    }

    Ok((terms_document_id, privacy_document_id))
}

async fn upsert_legal_notice_batch(
    pool: &PgPool,
    dedupe_key: &str,
    terms_document_id: Option<Uuid>,
    privacy_document_id: Option<Uuid>,
) -> Result<Uuid, (StatusCode, String)> {
    sqlx::query_scalar(
        "INSERT INTO legal_notice_batches (
            dedupe_key, terms_document_id, privacy_document_id
         )
         VALUES ($1, $2, $3)
         ON CONFLICT (dedupe_key) DO UPDATE
            SET dedupe_key = EXCLUDED.dedupe_key
         RETURNING id",
    )
    .bind(dedupe_key)
    .bind(terms_document_id)
    .bind(privacy_document_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to upsert legal notice batch: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create legal notice batch".to_string(),
        )
    })
}

async fn count_legal_notice_recipients(
    pool: &PgPool,
    recipient_selection: &RecipientSelection,
) -> Result<i64, (StatusCode, String)> {
    sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM users
         WHERE is_active = true
           AND email IS NOT NULL
           AND email_verified_at IS NOT NULL
           AND (
                ($1::uuid[] IS NULL AND $2::text[] IS NULL)
                OR ($1::uuid[] IS NOT NULL AND id = ANY($1))
                OR ($2::text[] IS NOT NULL AND lower(email) = ANY($2))
           )",
    )
    .bind(recipient_selection.recipient_ids.clone())
    .bind(recipient_selection.recipient_emails.clone())
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count legal notice recipients: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to count legal notice recipients".to_string(),
        )
    })
}

async fn count_sent_legal_notice_deliveries(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<i64, (StatusCode, String)> {
    let Some(batch_id) = batch_id else {
        return Ok(0);
    };

    sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM legal_email_deliveries led
         JOIN users ON users.id = led.user_id
         WHERE led.batch_id = $1
           AND led.status = 'sent'
           AND users.is_active = true
           AND users.email IS NOT NULL
           AND users.email_verified_at IS NOT NULL
           AND (
                ($2::uuid[] IS NULL AND $3::text[] IS NULL)
                OR ($2::uuid[] IS NOT NULL AND users.id = ANY($2))
                OR ($3::text[] IS NOT NULL AND lower(users.email) = ANY($3))
           )",
    )
    .bind(batch_id)
    .bind(recipient_selection.recipient_ids.clone())
    .bind(recipient_selection.recipient_emails.clone())
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count legal notice deliveries: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to count legal notice deliveries".to_string(),
        )
    })
}

async fn count_pending_legal_notice_recipients(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<i64, (StatusCode, String)> {
    sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM users
         WHERE is_active = true
           AND email IS NOT NULL
           AND email_verified_at IS NOT NULL
           AND (
                ($1::uuid[] IS NULL AND $2::text[] IS NULL)
                OR ($1::uuid[] IS NOT NULL AND id = ANY($1))
                OR ($2::text[] IS NOT NULL AND lower(email) = ANY($2))
           )
           AND (
                $3::uuid IS NULL
                OR NOT EXISTS (
                    SELECT 1
                    FROM legal_email_deliveries led
                    WHERE led.batch_id = $3
                      AND led.user_id = users.id
                      AND led.status = 'sent'
                )
           )",
    )
    .bind(recipient_selection.recipient_ids.clone())
    .bind(recipient_selection.recipient_emails.clone())
    .bind(batch_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count pending legal notice recipients: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to count pending legal notice recipients".to_string(),
        )
    })
}

async fn load_pending_legal_notice_recipients(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<Vec<LegalNoticeRecipient>, (StatusCode, String)> {
    sqlx::query_as::<_, LegalNoticeRecipient>(
        "SELECT id, email
         FROM users
         WHERE is_active = true
           AND email IS NOT NULL
           AND email_verified_at IS NOT NULL
           AND (
                ($1::uuid[] IS NULL AND $2::text[] IS NULL)
                OR ($1::uuid[] IS NOT NULL AND id = ANY($1))
                OR ($2::text[] IS NOT NULL AND lower(email) = ANY($2))
           )
           AND (
                $3::uuid IS NULL
                OR NOT EXISTS (
                    SELECT 1
                    FROM legal_email_deliveries led
                    WHERE led.batch_id = $3
                      AND led.user_id = users.id
                      AND led.status = 'sent'
                )
           )
         ORDER BY created_at ASC, id ASC
         LIMIT $4",
    )
    .bind(recipient_selection.recipient_ids.clone())
    .bind(recipient_selection.recipient_emails.clone())
    .bind(batch_id)
    .bind(recipient_selection.limit_or_max())
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to load legal notice recipients: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load legal notice recipients".to_string(),
        )
    })
}

fn build_legal_notice_email_data(documents: &[LegalNoticeDocument]) -> serde_json::Value {
    let email_documents: Vec<serde_json::Value> = documents
        .iter()
        .map(|document| {
            let requires_action =
                document.requires_blocking_reacceptance || document.requires_acknowledgment;
            serde_json::json!({
                "document_type": &document.document_type,
                "document_title": legal_document_title(&document.document_type),
                "version": &document.version,
                "effective_at": document.effective_at.format("%Y-%m-%d").to_string(),
                "url": &document.url,
                "requires_action": requires_action,
            })
        })
        .collect();

    let action_required = documents.iter().any(|document| {
        document.requires_blocking_reacceptance || document.requires_acknowledgment
    });

    serde_json::json!({
        "documents": email_documents,
        "action_required": action_required,
    })
}

async fn send_legal_notice_email(
    client: &reqwest::Client,
    email_service_url: &str,
    email_request: &serde_json::Value,
) -> Result<(), String> {
    let response = client
        .post(format!("{}/send", email_service_url))
        .json(email_request)
        .send()
        .await
        .map_err(|e| format!("Email service request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("Email service returned {}", status));
    }

    let email_response = response
        .json::<EmailServiceResponse>()
        .await
        .map_err(|e| format!("Failed to parse email service response: {}", e))?;

    if email_response.success {
        Ok(())
    } else {
        Err(email_response
            .message
            .unwrap_or_else(|| "Email service reported unsuccessful delivery".to_string()))
    }
}

async fn record_legal_notice_delivery(
    pool: &PgPool,
    batch_id: Uuid,
    user_id: Uuid,
    email: &str,
    status: &str,
    error: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO legal_email_deliveries (
            batch_id, user_id, email, status, error, sent_at, updated_at
         )
         VALUES (
            $1, $2, $3, $4, $5,
            CASE WHEN $4 = 'sent' THEN NOW() ELSE NULL END,
            NOW()
         )
         ON CONFLICT (batch_id, user_id) DO UPDATE SET
            email = EXCLUDED.email,
            status = EXCLUDED.status,
            error = EXCLUDED.error,
            sent_at = EXCLUDED.sent_at,
            updated_at = NOW()",
    )
    .bind(batch_id)
    .bind(user_id)
    .bind(email)
    .bind(status)
    .bind(error)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to record legal notice delivery: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to record legal notice delivery".to_string(),
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legal_notice_dedupe_key_includes_selected_documents() {
        let terms_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let privacy_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            legal_notice_dedupe_key(Some(terms_id), Some(privacy_id)),
            "terms=11111111-1111-1111-1111-111111111111;privacy=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            legal_notice_dedupe_key(Some(terms_id), None),
            "terms=11111111-1111-1111-1111-111111111111;privacy=none"
        );
        assert_eq!(
            legal_notice_dedupe_key(None, Some(privacy_id)),
            "terms=none;privacy=22222222-2222-2222-2222-222222222222"
        );
    }

    #[test]
    fn test_current_user_requires_no_action() {
        let status = compute_document_status(
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.accepted_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_outdated_user_requires_action() {
        let status = compute_document_status(
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                version: "2026-06-01".to_string(),
                occurred_at: None,
            }),
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
        );
        assert!(status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-06-01"));
        assert_eq!(status.accepted_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_pre_tracking_user_no_action() {
        // User has no legal event rows (predates tracking)
        let status = compute_document_status(
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
            None,
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.accepted_version, None);
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
                occurred_at: None,
            }),
        );
        assert!(!status.requires_action);
    }

    #[test]
    fn test_recipient_selection_normalizes_emails_and_limit() {
        let request = SendLegalNoticesRequest {
            dry_run: true,
            document_ids: None,
            recipient_ids: None,
            recipient_emails: Some(vec![
                " User@example.com ".to_string(),
                "other@example.com".to_string(),
                "user@example.com".to_string(),
            ]),
            limit: Some(25),
        };

        let selection = RecipientSelection::from_request(&request).unwrap();

        assert_eq!(
            selection.recipient_emails,
            Some(vec![
                "other@example.com".to_string(),
                "user@example.com".to_string(),
            ])
        );
        assert_eq!(selection.limit, Some(25));
    }

    #[test]
    fn test_recipient_selection_rejects_empty_ids() {
        let request = SendLegalNoticesRequest {
            dry_run: true,
            document_ids: None,
            recipient_ids: Some(Vec::new()),
            recipient_emails: None,
            limit: None,
        };

        let error = RecipientSelection::from_request(&request).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("recipient_ids"));
    }

    #[test]
    fn test_recipient_selection_rejects_invalid_email() {
        let request = SendLegalNoticesRequest {
            dry_run: true,
            document_ids: None,
            recipient_ids: None,
            recipient_emails: Some(vec!["not-an-email".to_string()]),
            limit: None,
        };

        let error = RecipientSelection::from_request(&request).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("Invalid recipient email"));
    }

    #[test]
    fn test_recipient_selection_rejects_zero_limit() {
        let request = SendLegalNoticesRequest {
            dry_run: true,
            document_ids: None,
            recipient_ids: None,
            recipient_emails: None,
            limit: Some(0),
        };

        let error = RecipientSelection::from_request(&request).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(error.1.contains("limit"));
    }
}

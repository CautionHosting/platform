// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, validation::validate_email};

#[derive(Debug, Clone, FromRow)]
struct LegalDocumentIdentity {
    id: Uuid,
    version: String,
    occurred_at: Option<DateTime<Utc>>,
}

/// The currently-active row for a document type, plus everything needed to
/// compute status/enforcement/display for it without further queries.
#[derive(Debug, Clone, FromRow)]
struct ActiveLegalDocument {
    id: Uuid,
    version: String,
    title: Option<String>,
    url: String,
    requires_blocking_reacceptance: bool,
    requires_acknowledgment: bool,
}

#[derive(Debug, Clone, FromRow)]
struct LegalNoticeDocument {
    id: Uuid,
    document_type: String,
    title: Option<String>,
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
    pub title: String,
    pub url: Option<String>,
    pub active_version: Option<String>,
    pub accepted_version: Option<String>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub requires_action: bool,
}

/// Legal status for a user across every document type that currently has
/// an active version, keyed by `document_type`. Not hardcoded to a fixed
/// set of types — whatever `legal_documents` has active shows up here.
/// BTreeMap (not HashMap) so the serialized order is stable across requests
/// — the frontend renders these in iteration order and a HashMap would
/// reshuffle the rows on every refresh.
pub type UserLegalStatus = BTreeMap<String, LegalDocumentStatus>;

#[derive(Debug, Serialize)]
pub struct PublicLegalDocumentSummary {
    pub document_type: String,
    pub title: String,
    pub url: String,
}

/// Failure modes for [`list_active_legal_documents`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListActiveLegalDocumentsError {
    #[error("could not list active legal documents [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListActiveLegalDocumentsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListActiveLegalDocumentsError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Public (unauthenticated) list of every currently-active document. The
/// registration screen renders this list to build its "by creating an
/// account, you agree to X and Y" notice, and signup records a consent
/// event for exactly these documents — so what's presented and what's
/// recorded always match, however many document types are configured.
#[tracing::instrument(skip_all, err)]
pub async fn list_active_legal_documents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PublicLegalDocumentSummary>>, ListActiveLegalDocumentsError> {
    use ListActiveLegalDocumentsErrorCtx as Ctx;

    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT document_type, title, url FROM legal_documents WHERE is_active = true ORDER BY document_type",
    )
    .fetch_all(&state.db)
    .await
    .inspect_err(|e| tracing::error!("Failed to list active legal documents: {:?}", e))
    .with_context(Ctx::query())?;

    Ok(Json(
        rows.into_iter()
            .map(|(document_type, title, url)| PublicLegalDocumentSummary {
                title: resolve_title(title.as_deref(), &document_type),
                document_type,
                url,
            })
            .collect(),
    ))
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
#[allow(dead_code)]
struct EmailServiceResponse {
    success: bool,
    message: Option<String>,
}

/// Failure modes for [`RecipientSelection::from_request`] (all source-less
/// domain failures).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RecipientSelectionError {
    #[error("recipient_ids must not be empty [{location}]")]
    EmptyIds {
        #[location]
        location: Location,
    },

    #[error("recipient_emails must not be empty [{location}]")]
    EmptyEmails {
        #[location]
        location: Location,
    },

    #[error("recipient_emails must not contain empty values [{location}]")]
    EmptyEmailValue {
        #[location]
        location: Location,
    },

    #[error("invalid recipient email '{email}' [{location}]")]
    InvalidEmail {
        email: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("limit must be greater than zero [{location}]")]
    ZeroLimit {
        #[location]
        location: Location,
    },
}

#[derive(Debug, Clone, Default)]
struct RecipientSelection {
    recipient_ids: Option<Vec<Uuid>>,
    recipient_emails: Option<Vec<String>>,
    limit: Option<i64>,
}

impl RecipientSelection {
    fn from_request(request: &SendLegalNoticesRequest) -> Result<Self, RecipientSelectionError> {
        use RecipientSelectionErrorCtx as Ctx;

        let recipient_ids = match request.recipient_ids.as_ref() {
            Some(ids) if ids.is_empty() => {
                return Err(RecipientSelectionError::EmptyIds {
                    location: std::panic::Location::caller(),
                });
            }
            Some(ids) => Some(ids.clone()),
            None => None,
        };

        let recipient_emails = match request.recipient_emails.as_ref() {
            Some(emails) if emails.is_empty() => {
                return Err(RecipientSelectionError::EmptyEmails {
                    location: std::panic::Location::caller(),
                });
            }
            Some(emails) => {
                let mut normalized = Vec::with_capacity(emails.len());
                for email in emails {
                    let trimmed = email.trim().to_lowercase();
                    if trimmed.is_empty() {
                        return Err(RecipientSelectionError::EmptyEmailValue {
                            location: std::panic::Location::caller(),
                        });
                    }
                    validate_email(&trimmed).with_context(Ctx::invalid_email(email.as_str()))?;
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
                return Err(RecipientSelectionError::ZeroLimit {
                    location: std::panic::Location::caller(),
                });
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

/// Display title for a document: the row's own `title` if set, else a
/// humanized form of its `document_type` (e.g. "terms_of_service" ->
/// "Terms Of Service"). Lets a new document type work without a code change.
fn resolve_title(title: Option<&str>, document_type: &str) -> String {
    match title {
        Some(t) if !t.trim().is_empty() => t.to_string(),
        _ => humanize_document_type(document_type),
    }
}

fn humanize_document_type(document_type: &str) -> String {
    document_type
        .split('_')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn legal_notice_dedupe_key(document_ids: &[Uuid]) -> String {
    let mut ids: Vec<String> = document_ids.iter().map(|id| id.to_string()).collect();
    ids.sort_unstable();
    ids.join(";")
}

/// Failure modes for [`get_active_document`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetActiveDocumentError {
    #[error("could not query active legal document '{document_type}' [{location}]")]
    Query {
        document_type: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Get the active version for a document type, or None if no active version exists.
#[tracing::instrument(skip_all, err)]
async fn get_active_document(
    pool: &PgPool,
    document_type: &str,
) -> Result<Option<ActiveLegalDocument>, GetActiveDocumentError> {
    use GetActiveDocumentErrorCtx as Ctx;

    sqlx::query_as(
        "SELECT id, version, title, url, requires_blocking_reacceptance, requires_acknowledgment
         FROM legal_documents
         WHERE document_type = $1 AND is_active = true",
    )
    .bind(document_type)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::query(document_type))
}

/// Failure modes for [`get_latest_user_document_by_type`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetLatestUserDocumentByTypeError {
    #[error("could not query latest user legal document '{document_type}' [{location}]")]
    Query {
        document_type: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Get the user's most recent legal event for a document type, of any
/// event of either affirmative type ("accepted" or "acknowledged"). Event
/// wording is derived from the document's own flags at accept time, not
/// fixed per document_type, so this can't match on one specific expected
/// string — but it must still exclude non-affirmative events. The
/// user_legal_events CHECK constraint also permits "declined" and
/// "notice_shown"; if either were ever the most recent row for a document,
/// an unfiltered "most recent event of any type" query would treat it as
/// satisfying the document and clear requires_action without real consent.
#[tracing::instrument(skip_all, err)]
async fn get_latest_user_document_by_type(
    pool: &PgPool,
    user_id: Uuid,
    document_type: &str,
) -> Result<Option<LegalDocumentIdentity>, GetLatestUserDocumentByTypeError> {
    use GetLatestUserDocumentByTypeErrorCtx as Ctx;

    sqlx::query_as(
        "SELECT
            legal_document_id AS id,
            document_version AS version,
            occurred_at
         FROM user_legal_events
         WHERE user_id = $1
           AND document_type = $2
           AND event_type IN ('accepted', 'acknowledged')
         ORDER BY occurred_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .bind(document_type)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::query(document_type))
}

/// Failure modes for [`user_predates_legal_tracking`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UserPredatesLegalTrackingError {
    #[error("could not query legal event history [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// True if the user has no legal event history at all (registered before
/// legal tracking existed), as opposed to having history for other document
/// types but not this one. See `compute_document_status` for why this
/// distinction matters.
#[tracing::instrument(skip_all, err)]
async fn user_predates_legal_tracking(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<bool, UserPredatesLegalTrackingError> {
    use UserPredatesLegalTrackingErrorCtx as Ctx;

    let has_any_event: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_legal_events WHERE user_id = $1)")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .with_context(Ctx::query())?;
    Ok(!has_any_event)
}

/// Failure modes for [`get_user_legal_status`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetUserLegalStatusError {
    #[error("could not query active document types [{location}]")]
    QueryTypes {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not check legal tracking history [{location}]")]
    PredatesTracking {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load active legal document [{location}]")]
    ActiveDocument {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load latest user legal document [{location}]")]
    UserDocument {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Get the full legal status for a user across every document type that
/// currently has an active version.
#[tracing::instrument(skip_all, err)]
pub async fn get_user_legal_status(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserLegalStatus, GetUserLegalStatusError> {
    use GetUserLegalStatusErrorCtx as Ctx;

    let document_types: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT document_type FROM legal_documents WHERE is_active = true ORDER BY document_type",
    )
    .fetch_all(pool)
    .await
    .with_context(Ctx::query_types())?;

    let predates_tracking = user_predates_legal_tracking(pool, user_id)
        .await
        .with_context(Ctx::predates_tracking())?;

    let mut status = BTreeMap::new();
    for document_type in document_types {
        let active = get_active_document(pool, &document_type)
            .await
            .with_context(Ctx::active_document())?;
        let user_doc = get_latest_user_document_by_type(pool, user_id, &document_type)
            .await
            .with_context(Ctx::user_document())?;
        status.insert(
            document_type.clone(),
            compute_document_status(&document_type, active.as_ref(), user_doc, predates_tracking),
        );
    }

    Ok(status)
}

/// Failure modes for [`get_blocking_document_requiring_acceptance`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetBlockingDocumentRequiringAcceptanceError {
    #[error("could not fetch legal status [{location}]")]
    LegalStatus {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not query blocking document types [{location}]")]
    QueryBlocking {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn get_blocking_document_requiring_acceptance(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<String>, GetBlockingDocumentRequiringAcceptanceError> {
    use GetBlockingDocumentRequiringAcceptanceErrorCtx as Ctx;

    let legal = get_user_legal_status(pool, user_id)
        .await
        .with_context(Ctx::legal_status())?;

    let blocking_types: Vec<String> = sqlx::query_scalar(
        "SELECT document_type FROM legal_documents
         WHERE is_active = true AND requires_blocking_reacceptance = true
         ORDER BY document_type",
    )
    .fetch_all(pool)
    .await
    .with_context(Ctx::query_blocking())?;

    for document_type in blocking_types {
        if legal
            .get(&document_type)
            .is_some_and(|status| status.requires_action)
        {
            return Ok(Some(document_type));
        }
    }

    Ok(None)
}

/// Compute legal status for a single document type.
///
/// `user_predates_tracking` distinguishes two different reasons a user can
/// have no event for this document type: they registered before legal
/// tracking existed at all (skip gating, a deliberate no-retroactive-gate
/// policy), vs. they have other legal history but this specific document
/// type was introduced after they last touched the flow (must gate — that's
/// the entire point of re-acceptance). Without this distinction, adding a
/// new document type would never gate any existing user, since no one has
/// an event for a type that didn't exist yet.
fn compute_document_status(
    document_type: &str,
    active_document: Option<&ActiveLegalDocument>,
    latest_user_document: Option<LegalDocumentIdentity>,
    user_predates_tracking: bool,
) -> LegalDocumentStatus {
    let active_version = active_document.map(|doc| doc.version.clone());
    let accepted_version = latest_user_document.as_ref().map(|doc| doc.version.clone());
    let accepted_at = latest_user_document
        .as_ref()
        .and_then(|doc| doc.occurred_at);

    // A document configured with both flags false is purely informational —
    // tracked, but never something a user must act on. Without this check, a
    // version bump on such a document would still flip requires_action and
    // pop the full-screen modal for everyone, which the flags say shouldn't
    // happen. Previously safe by coincidence (the two hardcoded types always
    // had exactly one flag set); no longer guaranteed once document_type is
    // an open string an operator configures.
    let action_capable = |doc: &ActiveLegalDocument| {
        doc.requires_blocking_reacceptance || doc.requires_acknowledgment
    };

    let requires_action = match (&active_document, &latest_user_document) {
        // Compare exact legal document rows, not just display versions.
        (Some(active), Some(user_doc)) => active.id != user_doc.id && action_capable(active),
        // Active version exists, user has no record for this type: gate
        // unless the user predates legal tracking entirely.
        (Some(active), None) => !user_predates_tracking && action_capable(active),
        // No active version: nothing to enforce
        (None, _) => false,
    };

    let title = resolve_title(
        active_document.and_then(|doc| doc.title.as_deref()),
        document_type,
    );
    let url = active_document.map(|doc| doc.url.clone());

    LegalDocumentStatus {
        title,
        url,
        active_version,
        accepted_version,
        accepted_at,
        requires_action,
    }
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

/// Failure modes for [`accept_legal_document`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum AcceptLegalDocumentError {
    #[error("could not query active legal version [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no active '{document_type}' document found [{location}]")]
    NotFound {
        document_type: String,
        #[location]
        location: Location,
    },

    #[error("could not record legal event [{location}]")]
    RecordEvent {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not fetch updated legal status [{location}]")]
    FetchStatus {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for AcceptLegalDocumentError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AcceptLegalDocumentError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AcceptLegalDocumentError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
            AcceptLegalDocumentError::RecordEvent { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AcceptLegalDocumentError::FetchStatus { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Accept/acknowledge the current active version of a legal document.
/// Records an append-only event and returns the updated legal status.
#[tracing::instrument(skip_all, err, fields(document_type = %payload.document_type))]
pub async fn accept_legal_document(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(payload): Json<AcceptLegalRequest>,
) -> Result<Json<AcceptLegalResponse>, AcceptLegalDocumentError> {
    use AcceptLegalDocumentErrorCtx as Ctx;

    let active_document = get_active_document(&state.db, &payload.document_type)
        .await
        .inspect_err(|e| tracing::error!("Failed to get active legal version: {:?}", e))
        .with_context(Ctx::query())?;

    let active_document = active_document.ok_or_else(|| AcceptLegalDocumentError::NotFound {
        document_type: payload.document_type.clone(),
        location: std::panic::Location::caller(),
    })?;
    let version = active_document.version.clone();

    // Event wording is derived from the document's own flags (set at publish
    // time via --blocking/--ack), not from a hardcoded document_type match,
    // so a new document type works without a code change.
    let event_type = if active_document.requires_blocking_reacceptance {
        "accepted"
    } else {
        "acknowledged"
    };

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
    .inspect_err(|e| tracing::error!("Failed to record legal event: {:?}", e))
    .with_context(Ctx::record_event())?;

    tracing::info!(
        "User {} {} {} version {}",
        auth.user_id,
        event_type,
        payload.document_type,
        version
    );

    let legal = get_user_legal_status(&state.db, auth.user_id)
        .await
        .inspect_err(|e| tracing::error!("Failed to fetch updated legal status: {:?}", e))
        .with_context(Ctx::fetch_status())?;

    Ok(Json(AcceptLegalResponse {
        success: true,
        document_type: payload.document_type,
        version,
        event_type: event_type.to_string(),
        legal,
    }))
}

/// Failure modes for [`send_legal_notices`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum SendLegalNoticesError {
    #[error("invalid legal notice request [{location}]")]
    InvalidRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load legal notice documents [{location}]")]
    DocumentsQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not query legal notice batch [{location}]")]
    BatchQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not create legal notice batch [{location}]")]
    BatchUpsert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not count legal notice recipients [{location}]")]
    CountRecipients {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not count legal notice deliveries [{location}]")]
    CountSent {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not count pending legal notice recipients [{location}]")]
    CountPending {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load legal notice recipients [{location}]")]
    LoadRecipients {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not create legal notice batch [{location}]")]
    BatchMissing {
        #[location]
        location: Location,
    },

    #[error("could not record legal notice delivery [{location}]")]
    RecordDelivery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SendLegalNoticesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            SendLegalNoticesError::InvalidRequest { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            SendLegalNoticesError::DocumentsQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::BatchQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::BatchUpsert { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::CountRecipients { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::CountSent { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::CountPending { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::LoadRecipients { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::BatchMissing { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            SendLegalNoticesError::RecordDelivery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn send_legal_notices(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendLegalNoticesRequest>,
) -> Result<Json<SendLegalNoticesResponse>, SendLegalNoticesError> {
    use SendLegalNoticesErrorCtx as Ctx;

    let recipient_selection =
        RecipientSelection::from_request(&payload).with_context(Ctx::invalid_request())?;
    let documents_result =
        load_legal_notice_documents(&state.db, payload.document_ids.as_deref()).await;
    let ctx = match &documents_result {
        Err(LoadLegalNoticeDocumentsError::Query { .. }) => Ctx::documents_query(),
        _ => Ctx::invalid_request(),
    };
    let documents = documents_result.with_context(ctx)?;
    let document_ids = legal_notice_document_ids(&documents).with_context(Ctx::invalid_request())?;
    let dedupe_key = legal_notice_dedupe_key(&document_ids);

    let existing_batch_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM legal_notice_batches WHERE dedupe_key = $1")
            .bind(&dedupe_key)
            .fetch_optional(&state.db)
            .await
            .inspect_err(|e| tracing::error!("Failed to query legal notice batch: {:?}", e))
            .with_context(Ctx::batch_query())?;

    let dry_run_batch_id = existing_batch_id;
    let batch_id = if payload.dry_run {
        dry_run_batch_id
    } else {
        Some(
            upsert_legal_notice_batch(&state.db, &dedupe_key, &document_ids)
                .await
                .with_context(Ctx::batch_upsert())?,
        )
    };

    let eligible_recipient_count = count_legal_notice_recipients(&state.db, &recipient_selection)
        .await
        .with_context(Ctx::count_recipients())?;
    let already_sent_count = count_sent_legal_notice_deliveries(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await
    .with_context(Ctx::count_sent())?;
    let pending_recipient_count = count_pending_legal_notice_recipients(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await
    .with_context(Ctx::count_pending())?;
    let recipients = load_pending_legal_notice_recipients(
        &state.db,
        batch_id.or(existing_batch_id),
        &recipient_selection,
    )
    .await
    .with_context(Ctx::load_recipients())?;
    let selected_recipient_count = recipients.len() as i64;
    let has_more = pending_recipient_count > selected_recipient_count;

    let response_documents = documents
        .iter()
        .map(|doc| LegalNoticeDocumentResponse {
            id: doc.id,
            document_type: doc.document_type.clone(),
            title: resolve_title(doc.title.as_deref(), &doc.document_type),
            version: doc.version.clone(),
            url: doc.url.clone(),
            effective_at: doc.effective_at,
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

    let batch_id = batch_id.ok_or_else(|| SendLegalNoticesError::BatchMissing {
        location: std::panic::Location::caller(),
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

        match send_legal_notice_email(&client, &email_service_url, &email_request).await {
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
                .await
                .with_context(Ctx::record_delivery())?;
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to send legal notice email to user {}: {:?}",
                    recipient.id,
                    error
                );
                failed_count += 1;
                record_legal_notice_delivery(
                    &state.db,
                    batch_id,
                    recipient.id,
                    &recipient.email,
                    "failed",
                    Some(error.message()),
                )
                .await
                .with_context(Ctx::record_delivery())?;
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

/// Failure modes for [`load_legal_notice_documents`]. The `EmptyIds`,
/// `NoneSelected`, and `CountMismatch` variants are source-less domain
/// failures; only `Query` carries an underlying error.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadLegalNoticeDocumentsError {
    #[error("document_ids must not be empty [{location}]")]
    EmptyIds {
        #[location]
        location: Location,
    },

    #[error("could not load legal notice documents [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no legal documents selected for notice [{location}]")]
    NoneSelected {
        #[location]
        location: Location,
    },

    #[error("one or more document_ids were not found [{location}]")]
    CountMismatch {
        #[location]
        location: Location,
    },
}

#[tracing::instrument(skip_all, err)]
async fn load_legal_notice_documents(
    pool: &PgPool,
    document_ids: Option<&[Uuid]>,
) -> Result<Vec<LegalNoticeDocument>, LoadLegalNoticeDocumentsError> {
    use LoadLegalNoticeDocumentsErrorCtx as Ctx;

    let documents = if let Some(document_ids) = document_ids {
        if document_ids.is_empty() {
            return Err(LoadLegalNoticeDocumentsError::EmptyIds {
                location: std::panic::Location::caller(),
            });
        }

        sqlx::query_as::<_, LegalNoticeDocument>(
            "SELECT id,
                    document_type,
                    title,
                    version,
                    url,
                    effective_at,
                    requires_blocking_reacceptance,
                    requires_acknowledgment
             FROM legal_documents
             WHERE id = ANY($1)
             ORDER BY document_type",
        )
        .bind(document_ids)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, LegalNoticeDocument>(
            "SELECT id,
                    document_type,
                    title,
                    version,
                    url,
                    effective_at,
                    requires_blocking_reacceptance,
                    requires_acknowledgment
             FROM legal_documents
             WHERE is_active = true
             ORDER BY document_type",
        )
        .fetch_all(pool)
        .await
    }
    .inspect_err(|e| tracing::error!("Failed to load legal notice documents: {:?}", e))
    .with_context(Ctx::query())?;

    if documents.is_empty() {
        return Err(LoadLegalNoticeDocumentsError::NoneSelected {
            location: std::panic::Location::caller(),
        });
    }

    if let Some(document_ids) = document_ids
        && documents.len() != document_ids.len()
    {
        return Err(LoadLegalNoticeDocumentsError::CountMismatch {
            location: std::panic::Location::caller(),
        });
    }

    Ok(documents)
}

/// Failure modes for [`legal_notice_document_ids`] (source-less domain
/// failure). Leaf error: no source-bearing variant, so it derives only
/// `thiserror` and is hand-built at its single call site.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LegalNoticeDocumentIdsError {
    #[error("legal notice batches can include at most one document of each type [{location}]")]
    DuplicateType { location: Location },
}

/// Validate at most one document per type in a notice batch, and collect
/// their ids. Generalized over an arbitrary set of document types instead
/// of two named slots.
#[tracing::instrument(skip_all, err)]
fn legal_notice_document_ids(
    documents: &[LegalNoticeDocument],
) -> Result<Vec<Uuid>, LegalNoticeDocumentIdsError> {
    let mut seen_types = HashSet::with_capacity(documents.len());

    for document in documents {
        if !seen_types.insert(document.document_type.as_str()) {
            return Err(LegalNoticeDocumentIdsError::DuplicateType {
                location: std::panic::Location::caller(),
            });
        }
    }

    Ok(documents.iter().map(|document| document.id).collect())
}

/// Failure modes for [`upsert_legal_notice_batch`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpsertLegalNoticeBatchError {
    #[error("failed to start legal notice batch transaction [{location}]")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to upsert legal notice batch [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to link legal notice batch document [{location}]")]
    Link {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to commit legal notice batch [{location}]")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn upsert_legal_notice_batch(
    pool: &PgPool,
    dedupe_key: &str,
    document_ids: &[Uuid],
) -> Result<Uuid, UpsertLegalNoticeBatchError> {
    use UpsertLegalNoticeBatchErrorCtx as Ctx;

    let mut tx = pool
        .begin()
        .await
        .inspect_err(|e| {
            tracing::error!("Failed to start legal notice batch transaction: {:?}", e);
        })
        .with_context(Ctx::begin())?;

    let batch_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_notice_batches (dedupe_key)
         VALUES ($1)
         ON CONFLICT (dedupe_key) DO UPDATE
            SET dedupe_key = EXCLUDED.dedupe_key
         RETURNING id",
    )
    .bind(dedupe_key)
    .fetch_one(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!("Failed to upsert legal notice batch: {:?}", e))
    .with_context(Ctx::insert())?;

    for document_id in document_ids {
        sqlx::query(
            "INSERT INTO legal_notice_batch_documents (batch_id, document_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(batch_id)
        .bind(document_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| {
            tracing::error!("Failed to link legal notice batch document: {:?}", e);
        })
        .with_context(Ctx::link())?;
    }

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!("Failed to commit legal notice batch: {:?}", e))
        .with_context(Ctx::commit())?;

    Ok(batch_id)
}

/// Failure modes for [`count_legal_notice_recipients`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CountLegalNoticeRecipientsError {
    #[error("failed to count legal notice recipients [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn count_legal_notice_recipients(
    pool: &PgPool,
    recipient_selection: &RecipientSelection,
) -> Result<i64, CountLegalNoticeRecipientsError> {
    use CountLegalNoticeRecipientsErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Failed to count legal notice recipients: {:?}", e))
    .with_context(Ctx::query())
}

/// Failure modes for [`count_sent_legal_notice_deliveries`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CountSentLegalNoticeDeliveriesError {
    #[error("failed to count legal notice deliveries [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn count_sent_legal_notice_deliveries(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<i64, CountSentLegalNoticeDeliveriesError> {
    use CountSentLegalNoticeDeliveriesErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Failed to count legal notice deliveries: {:?}", e))
    .with_context(Ctx::query())
}

/// Failure modes for [`count_pending_legal_notice_recipients`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CountPendingLegalNoticeRecipientsError {
    #[error("failed to count pending legal notice recipients [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn count_pending_legal_notice_recipients(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<i64, CountPendingLegalNoticeRecipientsError> {
    use CountPendingLegalNoticeRecipientsErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Failed to count pending legal notice recipients: {:?}", e))
    .with_context(Ctx::query())
}

/// Failure modes for [`load_pending_legal_notice_recipients`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadPendingLegalNoticeRecipientsError {
    #[error("failed to load legal notice recipients [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn load_pending_legal_notice_recipients(
    pool: &PgPool,
    batch_id: Option<Uuid>,
    recipient_selection: &RecipientSelection,
) -> Result<Vec<LegalNoticeRecipient>, LoadPendingLegalNoticeRecipientsError> {
    use LoadPendingLegalNoticeRecipientsErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Failed to load legal notice recipients: {:?}", e))
    .with_context(Ctx::query())
}

fn build_legal_notice_email_data(documents: &[LegalNoticeDocument]) -> serde_json::Value {
    let email_documents: Vec<serde_json::Value> = documents
        .iter()
        .map(|document| {
            let requires_action =
                document.requires_blocking_reacceptance || document.requires_acknowledgment;
            serde_json::json!({
                "document_type": &document.document_type,
                "document_title": resolve_title(document.title.as_deref(), &document.document_type),
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

/// Failure modes for [`send_legal_notice_email`]. The `ErrorStatus` and
/// `Unsuccessful` variants are source-less domain failures.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SendLegalNoticeEmailError {
    #[error("email service request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("email service returned error status {status} [{location}]")]
    ErrorStatus {
        status: reqwest::StatusCode,
        #[location]
        location: Location,
    },

    #[error("could not parse email service response [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("email service reported unsuccessful delivery [{location}]")]
    Unsuccessful {
        #[location]
        location: Location,
    },
}

impl SendLegalNoticeEmailError {
    /// Fixed wording recorded in the delivery log; never the underlying
    /// source or the internal location segment.
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Request { .. } => "email service request failed",
            Self::ErrorStatus { .. } => "email service returned an error status",
            Self::Parse { .. } => "could not parse email service response",
            Self::Unsuccessful { .. } => "email service reported unsuccessful delivery",
        }
    }
}

#[tracing::instrument(skip_all, err)]
async fn send_legal_notice_email(
    client: &reqwest::Client,
    email_service_url: &str,
    email_request: &serde_json::Value,
) -> Result<(), SendLegalNoticeEmailError> {
    use SendLegalNoticeEmailErrorCtx as Ctx;

    let response = client
        .post(format!("{}/send", email_service_url))
        .json(email_request)
        .send()
        .await
        .with_context(Ctx::request())?;

    let status = response.status();
    if !status.is_success() {
        return Err(SendLegalNoticeEmailError::ErrorStatus {
            status,
            location: std::panic::Location::caller(),
        });
    }

    let email_response = response
        .json::<EmailServiceResponse>()
        .await
        .with_context(Ctx::parse())?;

    if email_response.success {
        Ok(())
    } else {
        Err(SendLegalNoticeEmailError::Unsuccessful {
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`record_legal_notice_delivery`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RecordLegalNoticeDeliveryError {
    #[error("failed to record legal notice delivery [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn record_legal_notice_delivery(
    pool: &PgPool,
    batch_id: Uuid,
    user_id: Uuid,
    email: &str,
    status: &str,
    error: Option<&str>,
) -> Result<(), RecordLegalNoticeDeliveryError> {
    use RecordLegalNoticeDeliveryErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Failed to record legal notice delivery: {:?}", e))
    .with_context(Ctx::query())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_doc(id: Uuid, version: &str, blocking: bool, ack: bool) -> ActiveLegalDocument {
        ActiveLegalDocument {
            id,
            version: version.to_string(),
            title: None,
            url: "https://example.com/doc".to_string(),
            requires_blocking_reacceptance: blocking,
            requires_acknowledgment: ack,
        }
    }

    #[test]
    fn test_humanize_document_type() {
        assert_eq!(
            humanize_document_type("terms_of_service"),
            "Terms Of Service"
        );
        assert_eq!(humanize_document_type("privacy_notice"), "Privacy Notice");
        assert_eq!(humanize_document_type("dpa"), "Dpa");
    }

    #[test]
    fn test_resolve_title_prefers_explicit_title() {
        assert_eq!(
            resolve_title(Some("Data Processing Agreement"), "dpa"),
            "Data Processing Agreement"
        );
        assert_eq!(resolve_title(None, "dpa"), "Dpa");
        assert_eq!(resolve_title(Some("  "), "dpa"), "Dpa");
    }

    #[test]
    fn test_legal_notice_dedupe_key_is_order_independent_over_n_documents() {
        let a = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let b = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let c = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();

        assert_eq!(
            legal_notice_dedupe_key(&[a, b, c]),
            legal_notice_dedupe_key(&[c, a, b])
        );
        assert_eq!(legal_notice_dedupe_key(&[a]), a.to_string());
    }

    #[test]
    fn test_current_user_requires_no_action() {
        let id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let status = compute_document_status(
            "terms_of_service",
            Some(&active_doc(id, "2026-04-08", true, false)),
            Some(LegalDocumentIdentity {
                id,
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
            false,
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.accepted_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.title, "Terms Of Service");
    }

    #[test]
    fn test_outdated_user_requires_action() {
        let active_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let old_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let status = compute_document_status(
            "terms_of_service",
            Some(&active_doc(active_id, "2026-06-01", true, false)),
            Some(LegalDocumentIdentity {
                id: old_id,
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
            false,
        );
        assert!(status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-06-01"));
        assert_eq!(status.accepted_version.as_deref(), Some("2026-04-08"));
    }

    #[test]
    fn test_pre_tracking_user_no_action() {
        // User has zero legal event rows across every type (predates all
        // tracking) - do not retroactively gate.
        let id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let status = compute_document_status(
            "terms_of_service",
            Some(&active_doc(id, "2026-04-08", true, false)),
            None,
            true,
        );
        assert!(!status.requires_action);
        assert_eq!(status.active_version.as_deref(), Some("2026-04-08"));
        assert_eq!(status.accepted_version, None);
    }

    #[test]
    fn test_new_document_type_gates_user_with_other_legal_history() {
        // User has legal history (e.g. accepted ToS/Privacy at signup) but
        // none for this type, because it was published after they signed
        // up. Must gate - this is the whole point of adding a new document
        // type. Regression test for a bug where `(Some(_), None) => false`
        // meant a newly-added document type never gated anyone.
        let id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let status = compute_document_status(
            "dpa",
            Some(&active_doc(id, "2026-08-01", true, false)),
            None,
            false,
        );
        assert!(status.requires_action);
    }

    #[test]
    fn test_informational_document_never_requires_action() {
        // Both flags false = purely informational, tracked but never
        // something a user must act on. A version bump must not pop the
        // full-screen modal. Regression test: requires_action used to
        // compare document IDs only, ignoring the flags entirely.
        let old_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let new_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        // Version changed, user has an old record: would gate if flags were
        // ignored.
        let status = compute_document_status(
            "changelog",
            Some(&active_doc(new_id, "2026-06-01", false, false)),
            Some(LegalDocumentIdentity {
                id: old_id,
                version: "2026-01-01".to_string(),
                occurred_at: None,
            }),
            false,
        );
        assert!(!status.requires_action);

        // No record at all, user has other legal history: would gate if
        // flags were ignored (this is the exact shape of the new-type-gates
        // regression test above, minus the flags).
        let status_no_record = compute_document_status(
            "changelog",
            Some(&active_doc(new_id, "2026-06-01", false, false)),
            None,
            false,
        );
        assert!(!status_no_record.requires_action);
    }

    #[test]
    fn test_no_active_version_no_action() {
        let status = compute_document_status("terms_of_service", None, None, false);
        assert!(!status.requires_action);
        assert_eq!(status.active_version, None);
        assert_eq!(status.url, None);
    }

    #[test]
    fn test_no_active_version_with_user_event_no_action() {
        // Edge case: user accepted a version that's since been deactivated
        // with no replacement. Should not require action.
        let status = compute_document_status(
            "terms_of_service",
            None,
            Some(LegalDocumentIdentity {
                id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                version: "2026-04-08".to_string(),
                occurred_at: None,
            }),
            false,
        );
        assert!(!status.requires_action);
    }

    #[test]
    fn test_legal_notice_document_ids_rejects_duplicate_type_across_n_documents() {
        let make = |id: Uuid, document_type: &str| LegalNoticeDocument {
            id,
            document_type: document_type.to_string(),
            title: None,
            version: "2026-01-01".to_string(),
            url: "https://example.com".to_string(),
            effective_at: Utc::now(),
            requires_blocking_reacceptance: false,
            requires_acknowledgment: false,
        };

        let documents = vec![
            make(Uuid::new_v4(), "terms_of_service"),
            make(Uuid::new_v4(), "privacy_notice"),
            make(Uuid::new_v4(), "dpa"),
        ];
        assert!(legal_notice_document_ids(&documents).is_ok());

        let dup_type_id = documents[0].document_type.clone();
        let documents_with_dup = vec![
            make(Uuid::new_v4(), &dup_type_id),
            make(Uuid::new_v4(), &dup_type_id),
        ];
        let error = legal_notice_document_ids(&documents_with_dup).unwrap_err();
        assert!(matches!(
            error,
            LegalNoticeDocumentIdsError::DuplicateType { .. }
        ));
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
        assert!(matches!(error, RecipientSelectionError::EmptyIds { .. }));
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
        assert!(matches!(
            error,
            RecipientSelectionError::InvalidEmail { .. }
        ));
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
        assert!(matches!(error, RecipientSelectionError::ZeroLimit { .. }));
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Bounded history: failed attempts (deployment rows) and switch/destroy
//! operations (`deployment_events`: the request and its latest outcome),
//! newest first, tenant-scoped, keyset-paged on (time, id).

use crate::{AppState, AuthContext};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 50;

pub(crate) fn history_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// Failure of [`history_cursor`] (source-less leaf error).
#[derive(Debug, thiserror::Error)]
pub(crate) enum IncompleteCursorError {
    #[error("before_at and before_id must be given together [{location}]")]
    Incomplete { location: Location },
}

/// A cursor needs both parts; neither means the first page.
pub(crate) fn history_cursor(
    before_at: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
) -> Result<Option<HistoryCursor>, IncompleteCursorError> {
    match (before_at, before_id) {
        (Some(before_at), Some(before_id)) => Ok(Some(HistoryCursor {
            before_at,
            before_id,
        })),
        (None, None) => Ok(None),
        _ => Err(IncompleteCursorError::Incomplete {
            location: std::panic::Location::caller(),
        }),
    }
}

/// The last entry of a page: the next page starts strictly after it.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HistoryCursor {
    pub(crate) before_at: DateTime<Utc>,
    pub(crate) before_id: Uuid,
}

#[derive(serde::Deserialize)]
pub(crate) struct HistoryQuery {
    before_at: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub(crate) struct HistoryEntry {
    pub(crate) kind: String,
    pub(crate) id: Uuid,
    pub(crate) at: DateTime<Utc>,
    pub(crate) completed_at: Option<DateTime<Utc>>,
    pub(crate) operation: Option<String>,
    pub(crate) outcome: String,
    pub(crate) target_deployment_id: Option<Uuid>,
    pub(crate) previous_deployment_id: Option<Uuid>,
    pub(crate) commit_sha: Option<String>,
    pub(crate) commit_subject: Option<String>,
    pub(crate) pushed_ref: Option<String>,
    pub(crate) failure_kind: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) actor: Option<String>,
    pub(crate) auth_method: Option<String>,
    pub(crate) signed_request_id: Option<Uuid>,
    pub(crate) signed_request_status: Option<i32>,
    pub(crate) signed_request_completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct HistoryPage {
    pub(crate) entries: Vec<HistoryEntry>,
    pub(crate) next: Option<HistoryCursor>,
}

/// Failure modes for [`history_page`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to read the history of app {app_id} [{location}]")]
pub(crate) struct HistoryError {
    app_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

impl IntoResponse for HistoryError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "history read failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "History is unavailable." })),
        )
            .into_response()
    }
}

const HISTORY: &str = "SELECT h.* FROM (
        SELECT 'attempt' AS kind, d.id, d.failed_at AS at, NULL::timestamptz AS completed_at,
               NULL::text AS operation, 'failed' AS outcome,
               d.id AS target_deployment_id, NULL::uuid AS previous_deployment_id,
               d.commit_sha, d.commit_subject, d.pushed_ref, d.failure_kind, d.error,
               NULL::text AS actor, NULL::text AS auth_method, NULL::uuid AS signed_request_id,
               NULL::int AS signed_request_status, NULL::timestamptz AS signed_request_completed_at
        FROM app_deployments d
        WHERE d.app_id = $1 AND d.failed_at IS NOT NULL
        UNION ALL
        SELECT 'operation', r.operation_id, r.created_at, o.created_at, r.operation,
               COALESCE(o.outcome, 'requested'), t.id, p.id,
               t.commit_sha, t.commit_subject, t.pushed_ref, NULL, o.error,
               u.username, r.auth_method, r.signed_request_id, s.response_status, s.completed_at
        FROM deployment_events r
        LEFT JOIN LATERAL (
            SELECT x.outcome, x.error, x.created_at FROM deployment_events x
            WHERE x.operation_id = r.operation_id AND x.outcome <> 'requested'
            ORDER BY x.created_at DESC, x.id DESC LIMIT 1
        ) o ON true
        -- Scoped to the event's app, and the IDs are the joined rows' (not the event's
        -- columns): another app's deployment is neither named nor described.
        LEFT JOIN app_deployments t ON t.id = r.target_deployment_id AND t.app_id = r.app_id
        LEFT JOIN app_deployments p ON p.id = r.previous_deployment_id AND p.app_id = r.app_id
        LEFT JOIN users u ON u.id = r.actor_user_id
        LEFT JOIN signed_request_audit s ON s.id = r.signed_request_id
        WHERE r.app_id = $1 AND r.outcome = 'requested'
    ) h
    WHERE $2::timestamptz IS NULL OR (h.at, h.id) < ($2, $3::uuid)
    ORDER BY h.at DESC, h.id DESC
    LIMIT $4";

/// `None` when the user is no member of the app's organization.
pub(crate) async fn history_page(
    db: &PgPool,
    user_id: Uuid,
    app_id: Uuid,
    cursor: Option<HistoryCursor>,
    limit: i64,
) -> Result<Option<HistoryPage>, HistoryError> {
    let ctx = || HistoryErrorCtx::new(app_id);
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM compute_resources cr
             JOIN organization_members om ON om.organization_id = cr.organization_id AND om.user_id = $2
             WHERE cr.id = $1)",
    )
    .bind(app_id)
    .bind(user_id)
    .fetch_one(db)
    .await
    .with_context(ctx())?;
    if !member {
        return Ok(None);
    }
    let mut entries: Vec<HistoryEntry> = sqlx::query_as(HISTORY)
        .bind(app_id)
        .bind(cursor.map(|c| c.before_at))
        .bind(cursor.map(|c| c.before_id))
        .bind(limit + 1)
        .fetch_all(db)
        .await
        .with_context(ctx())?;
    let next = if entries.len() as i64 > limit {
        entries.truncate(limit as usize);
        entries.last().map(|entry| HistoryCursor {
            before_at: entry.at,
            before_id: entry.id,
        })
    } else {
        None
    };
    Ok(Some(HistoryPage { entries, next }))
}

pub(crate) async fn history_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(app_id): Path<Uuid>,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, HistoryError> {
    let Ok(cursor) = history_cursor(query.before_at, query.before_id) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "before_at and before_id go together." })),
        )
            .into_response());
    };
    Ok(
        match history_page(
            &state.db,
            auth.user_id,
            app_id,
            cursor,
            history_limit(query.limit),
        )
        .await?
        {
            Some(page) => Json(page).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "App not found." })),
            )
                .into_response(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_pages_are_bounded() {
        assert_eq!(history_limit(None), 20);
        assert_eq!(history_limit(Some(0)), 1);
        assert_eq!(history_limit(Some(500)), 50);
    }

    #[test]
    fn cursor_parts_come_together() {
        let (at, id) = (Utc::now(), Uuid::new_v4());
        assert_eq!(history_cursor(None, None).unwrap(), None);
        assert_eq!(
            history_cursor(Some(at), Some(id)).unwrap(),
            Some(HistoryCursor {
                before_at: at,
                before_id: id
            })
        );
        assert!(history_cursor(Some(at), None).is_err());
        assert!(history_cursor(None, Some(id)).is_err());
    }
}

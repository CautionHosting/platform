// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Read handlers for deployments: `GET /resources/{id}/deployments`,
//! `GET /resources/{id}/deployments/{deployment_id}` and `GET /deployments/{id}`.
//! The last is for session callers that know only the deployment: the gateway
//! authorizes SSH keys against the app ID in the path, so it is not SSH-signable.

use super::LIFECYCLE_DEPLOYMENTS;
use super::lifecycle::{Role, role_for};
use crate::{AppState, AuthContext, ec2, fully_managed_capacity};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The address an operator reaches a deployment at: the app's stable IP for
/// the live deployment, the instance's current IP otherwise. A candidate's IP
/// changes on stop/start and after a switch away from it, so it is never read
/// from a stored column.
pub(crate) fn endpoint_ip(
    role: Role,
    stable_ip: Option<&str>,
    current_instance_ip: Option<&str>,
) -> Option<String> {
    match role {
        Role::Live => stable_ip.map(str::to_string),
        Role::Candidate => current_instance_ip.map(str::to_string),
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DeploymentView {
    id: Uuid,
    app_id: Uuid,
    role: &'static str,
    status: String,
    failure_kind: Option<String>,
    pushed_ref: Option<String>,
    commit_sha: Option<String>,
    commit_subject: Option<String>,
    instance_id: Option<String>,
    instance_type: Option<String>,
    public_ip: Option<String>,
    created_at: DateTime<Utc>,
    running_at: Option<DateTime<Utc>>,
    activated_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    error: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub(super) struct DeploymentRow {
    pub(super) id: Uuid,
    pub(super) app_id: Uuid,
    status: String,
    failure_kind: Option<String>,
    pushed_ref: Option<String>,
    commit_sha: Option<String>,
    commit_subject: Option<String>,
    instance_id: Option<String>,
    instance_type: Option<String>,
    region: Option<String>,
    created_at: DateTime<Utc>,
    running_at: Option<DateTime<Utc>>,
    activated_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    error: Option<String>,
    pub(super) live_deployment_id: Option<Uuid>,
    /// The app Elastic IP.
    pub(super) stable_ip: Option<String>,
}

impl DeploymentRow {
    fn role(&self) -> Role {
        role_for(self.live_deployment_id, self.id)
    }

    /// Only a Running candidate has an instance address to look up; the live
    /// deployment answers with the stable IP.
    fn needs_instance_ip(&self) -> bool {
        self.role() == Role::Candidate && self.status == "running"
    }

    pub(super) fn into_view(self, current_instance_ip: Option<&str>) -> DeploymentView {
        let role = self.role();
        DeploymentView {
            public_ip: endpoint_ip(role, self.stable_ip.as_deref(), current_instance_ip),
            role: role.as_str(),
            id: self.id,
            app_id: self.app_id,
            status: self.status,
            failure_kind: self.failure_kind,
            pushed_ref: self.pushed_ref,
            commit_sha: self.commit_sha,
            commit_subject: self.commit_subject,
            instance_id: self.instance_id,
            instance_type: self.instance_type,
            created_at: self.created_at,
            running_at: self.running_at,
            activated_at: self.activated_at,
            failed_at: self.failed_at,
            error: self.error,
        }
    }
}

/// Failure modes for [`query_rows`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(super) enum QueryRowsError {
    #[error("database error while reading deployments [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// The deployments of the deployments-lifecycle apps of the caller's
/// organizations, optionally narrowed to one app and/or one deployment.
pub(super) async fn query_rows(
    db: &PgPool,
    user_id: Uuid,
    app_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
) -> Result<Vec<DeploymentRow>, QueryRowsError> {
    sqlx::query_as(
        "SELECT d.id, d.app_id, d.status, d.failure_kind, d.pushed_ref, d.commit_sha,
                d.commit_subject, d.instance_id, d.instance_type,
                COALESCE(d.region, cr.region) AS region, d.created_at, d.running_at,
                d.activated_at, d.failed_at, d.error,
                cr.live_deployment_id, cr.public_ip AS stable_ip
         FROM app_deployments d
         JOIN compute_resources cr ON cr.id = d.app_id
         JOIN organization_members om
              ON om.organization_id = cr.organization_id AND om.user_id = $1
         WHERE cr.lifecycle = $4 AND cr.destroyed_at IS NULL
           AND ($2::uuid IS NULL OR d.app_id = $2)
           AND ($3::uuid IS NULL OR d.id = $3)
         ORDER BY d.created_at DESC, d.id",
    )
    .bind(user_id)
    .bind(app_id)
    .bind(deployment_id)
    .bind(LIFECYCLE_DEPLOYMENTS)
    .fetch_all(db)
    .await
    .with_context(QueryRowsErrorCtx::database())
}

/// Bounds one EC2 lookup, so a slow answer delays a read by at most this long.
const INSTANCE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The instance's current address from EC2, or `None` when it has none or EC2
/// cannot be read: one unreadable instance must not fail the whole read.
async fn current_instance_ip(row: &DeploymentRow) -> Option<String> {
    let (Some(instance_id), Some(region)) = (row.instance_id.as_deref(), row.region.as_deref())
    else {
        return None;
    };
    let credentials = fully_managed_capacity::platform_credentials_for_region(region);
    let client = ec2::Ec2Client::new(&credentials);
    match tokio::time::timeout(
        INSTANCE_LOOKUP_TIMEOUT,
        client.describe_instance_runtime(instance_id),
    )
    .await
    {
        Ok(Ok(runtime)) => runtime
            .filter(|runtime| runtime.state == "running")
            .and_then(|runtime| runtime.public_ip),
        Ok(Err(error)) => {
            tracing::warn!(
                deployment_id = %row.id,
                error = ?error,
                "failed to read the deployment instance address from EC2"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                deployment_id = %row.id,
                "timed out reading the deployment instance address from EC2"
            );
            None
        }
    }
}

async fn load_views(
    db: &PgPool,
    user_id: Uuid,
    app_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
) -> Result<Vec<DeploymentView>, QueryRowsError> {
    let rows = query_rows(db, user_id, app_id, deployment_id).await?;
    let addresses = futures::future::join_all(rows.iter().map(|row| async {
        if row.needs_instance_ip() {
            current_instance_ip(row).await
        } else {
            None
        }
    }))
    .await;
    Ok(rows
        .into_iter()
        .zip(addresses)
        .map(|(row, ip)| row.into_view(ip.as_deref()))
        .collect())
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Failure modes for [`list_handler`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to list the deployments of app {app_id} [{location}]")]
pub(crate) struct ListDeploymentsError {
    app_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

impl IntoResponse for ListDeploymentsError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "failed to list deployments");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list deployments.",
        )
    }
}

pub(crate) async fn list_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(app_id): Path<Uuid>,
) -> Result<Json<Vec<DeploymentView>>, ListDeploymentsError> {
    load_views(&state.db, auth.user_id, Some(app_id), None)
        .await
        .map(Json)
        .with_context(ListDeploymentsErrorCtx::new(app_id))
}

/// Failure modes for [`get_in_app_handler`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetDeploymentInAppError {
    #[error("deployment {deployment_id} not found in app {app_id} [{location}]")]
    NotFound {
        app_id: Uuid,
        deployment_id: Uuid,
        location: Location,
    },
    #[error("failed to read deployment {deployment_id} of app {app_id} [{location}]")]
    Load {
        app_id: Uuid,
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetDeploymentInAppError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound { .. } => error_response(StatusCode::NOT_FOUND, "Deployment not found."),
            Self::Load { .. } => {
                tracing::error!(error = ?self, "failed to read a deployment");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read the deployment.",
                )
            }
        }
    }
}

/// 404 unless the deployment belongs to that app.
pub(crate) async fn get_in_app_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((app_id, deployment_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeploymentView>, GetDeploymentInAppError> {
    use GetDeploymentInAppErrorCtx as Ctx;

    load_views(&state.db, auth.user_id, Some(app_id), Some(deployment_id))
        .await
        .with_context(Ctx::load(app_id, deployment_id))?
        .pop()
        .map(Json)
        .ok_or_else(|| GetDeploymentInAppError::NotFound {
            app_id,
            deployment_id,
            location: std::panic::Location::caller(),
        })
}

/// Failure modes for [`get_handler`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetDeploymentError {
    #[error("deployment {deployment_id} not found [{location}]")]
    NotFound {
        deployment_id: Uuid,
        location: Location,
    },
    #[error("failed to read deployment {deployment_id} [{location}]")]
    Load {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetDeploymentError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound { .. } => error_response(StatusCode::NOT_FOUND, "Deployment not found."),
            Self::Load { .. } => {
                tracing::error!(error = ?self, "failed to read a deployment");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read the deployment.",
                )
            }
        }
    }
}

/// For callers that know only the deployment ID: the app is derived from it.
pub(crate) async fn get_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(deployment_id): Path<Uuid>,
) -> Result<Json<DeploymentView>, GetDeploymentError> {
    use GetDeploymentErrorCtx as Ctx;

    load_views(&state.db, auth.user_id, None, Some(deployment_id))
        .await
        .with_context(Ctx::load(deployment_id))?
        .pop()
        .map(Json)
        .ok_or_else(|| GetDeploymentError::NotFound {
            deployment_id,
            location: std::panic::Location::caller(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: Uuid, status: &str, live_deployment_id: Option<Uuid>) -> DeploymentRow {
        DeploymentRow {
            id,
            app_id: Uuid::new_v4(),
            status: status.to_string(),
            failure_kind: None,
            pushed_ref: None,
            commit_sha: None,
            commit_subject: None,
            instance_id: Some("i-0123".to_string()),
            instance_type: None,
            region: Some("us-east-1".to_string()),
            created_at: Utc::now(),
            running_at: None,
            activated_at: None,
            failed_at: None,
            error: None,
            live_deployment_id,
            stable_ip: Some("198.51.100.42".to_string()),
        }
    }

    #[test]
    fn deployment_endpoint_prefers_current_instance_ip() {
        assert_eq!(
            endpoint_ip(Role::Live, Some("198.51.100.42"), Some("203.0.113.9")).as_deref(),
            Some("198.51.100.42")
        );
        // A candidate's IP changes on stop/start and after a switch away from it.
        assert_eq!(
            endpoint_ip(Role::Candidate, Some("198.51.100.42"), Some("203.0.113.9")).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            endpoint_ip(Role::Candidate, Some("198.51.100.42"), None),
            None
        );
    }

    #[test]
    fn only_a_running_candidate_looks_up_its_instance_address() {
        let (live, other) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(row(other, "running", Some(live)).needs_instance_ip());
        assert!(row(other, "running", None).needs_instance_ip());
        for status in [
            "reserved",
            "building",
            "provisioning",
            "failed",
            "destroyed",
        ] {
            assert!(
                !row(other, status, Some(live)).needs_instance_ip(),
                "{status}"
            );
        }
        // The live deployment answers with the stable IP, without asking EC2.
        assert!(!row(live, "running", Some(live)).needs_instance_ip());
    }

    #[test]
    fn view_role_and_address_follow_the_live_pointer() {
        let (live, other) = (Uuid::new_v4(), Uuid::new_v4());
        let view = serde_json::to_value(row(live, "running", Some(live)).into_view(None)).unwrap();
        assert_eq!(view["role"], "live");
        assert_eq!(view["public_ip"], "198.51.100.42");
        let view =
            serde_json::to_value(row(other, "running", Some(live)).into_view(Some("203.0.113.9")))
                .unwrap();
        assert_eq!(view["role"], "candidate");
        assert_eq!(view["public_ip"], "203.0.113.9");
        // Nothing is live yet: every deployment is a candidate and the app IP is not theirs.
        let view = serde_json::to_value(row(other, "failed", None).into_view(None)).unwrap();
        assert_eq!(view["role"], "candidate");
        assert!(view["public_ip"].is_null());
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Read handlers for deployments: `GET /resources/{id}/deployments`,
//! `GET /resources/{id}/deployments/{deployment_id}` and `GET /deployments/{id}`.
//! The last is for session callers that know only the deployment: the gateway
//! authorizes SSH keys against the app ID in the path, so it is not SSH-signable.

use super::LIFECYCLE_DEPLOYMENTS;
use super::account;
use super::lifecycle::{Role, role_for};
use super::summary;
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
use std::time::Duration;
use uuid::Uuid;

/// SQL predicate over `app_deployments d`: an await-address build that has never
/// held the app address, so it has no certificate yet. Shared by the deployment
/// view and the switch, so both always agree.
pub(crate) const TLS_AFTER_SWITCH_SQL: &str = "(COALESCE((d.configuration->>'tls_await_app_address')::boolean, false) AND d.activated_at IS NULL)";

/// The address an operator reaches a deployment at: the app's stable IP for
/// the live deployment, the instance's current IP otherwise. A candidate's IP
/// changes on stop/start and after a switch away from it, so it is never read
/// from a stored column. A lost live deployment has no address: AWS has
/// already released the stable IP.
pub(crate) fn endpoint_ip(
    role: Role,
    runtime_lost: bool,
    stable_ip: Option<&str>,
    current_instance_ip: Option<&str>,
) -> Option<String> {
    match role {
        Role::Live if runtime_lost => None,
        Role::Live => stable_ip.map(str::to_string),
        Role::Candidate => current_instance_ip.map(str::to_string),
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DeploymentView {
    pub(crate) id: Uuid,
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
    bundle_hash: Option<String>,
    /// An await-address build that has never held the app address.
    tls_after_switch: bool,
    /// Holds resources or a candidate slot (`summary::is_retained`).
    pub(crate) retained: bool,
    pub(crate) region: Option<String>,
    pub(crate) enclave_cpus: Option<u64>,
    pub(crate) enclave_memory_mb: Option<u64>,
    /// Debug build; `None` until the configuration is recorded (when it goes Running).
    debug_mode: Option<bool>,
    /// Instance price at the configured margin over 730 hours; `None` when unknown
    /// or when no instance is billed.
    pub(crate) estimated_monthly_usd: Option<f64>,
    pub(crate) cleaned_up_at: Option<DateTime<Utc>>,
    pub(crate) destroyed_at: Option<DateTime<Utc>>,
    /// `done` or `pending` for a failed or destroyed deployment (`summary::cleanup_state`).
    cleanup: Option<&'static str>,
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
    bundle_hash: Option<String>,
    tls_after_switch: bool,
    cleaned_up_at: Option<DateTime<Utc>>,
    destroyed_at: Option<DateTime<Utc>>,
    configuration: serde_json::Value,
    pub(super) live_deployment_id: Option<Uuid>,
    /// The app Elastic IP.
    pub(super) stable_ip: Option<String>,
    /// The app network lives in a linked (BYOC) account.
    linked: bool,
    /// Hourly price at the configured margin; set by `load_views`, not a column.
    #[sqlx(skip)]
    pub(super) hourly_usd: Option<f64>,
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
        let cleaned_up = self.cleaned_up_at.is_some();
        let retained = summary::is_retained(&self.status, cleaned_up);
        let billed = summary::bills_instance(
            &self.status,
            cleaned_up,
            self.instance_id.as_deref(),
            self.failure_kind.as_deref(),
        );
        let estimated_monthly_usd = billed
            .then(|| summary::monthly_estimate(self.hourly_usd))
            .flatten();
        let enclave_cpus = self
            .configuration
            .get("cpus")
            .and_then(serde_json::Value::as_u64);
        let enclave_memory_mb = self
            .configuration
            .get("memory_mb")
            .and_then(serde_json::Value::as_u64);
        let debug_mode = self
            .configuration
            .get("debug")
            .and_then(serde_json::Value::as_bool);
        DeploymentView {
            public_ip: endpoint_ip(
                role,
                self.status == "failed" && self.failure_kind.as_deref() == Some("runtime_lost"),
                self.stable_ip.as_deref(),
                current_instance_ip,
            ),
            cleanup: summary::cleanup_state(&self.status, cleaned_up),
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
            bundle_hash: self.bundle_hash,
            tls_after_switch: self.tls_after_switch,
            retained,
            region: self.region,
            enclave_cpus,
            enclave_memory_mb,
            debug_mode,
            estimated_monthly_usd,
            cleaned_up_at: self.cleaned_up_at,
            destroyed_at: self.destroyed_at,
        }
    }
}

/// Failure modes for [`query_rows_with`].
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
/// Every row; the handlers use [`query_rows_with`], so this is for tests.
#[cfg(test)]
pub(super) async fn query_rows(
    db: &PgPool,
    user_id: Uuid,
    app_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
) -> Result<Vec<DeploymentRow>, QueryRowsError> {
    query_rows_with(db, user_id, app_id, deployment_id, false).await
}

/// [`query_rows`], optionally only the retained rows (`summary::is_retained`).
pub(super) async fn query_rows_with(
    db: &PgPool,
    user_id: Uuid,
    app_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
    retained_only: bool,
) -> Result<Vec<DeploymentRow>, QueryRowsError> {
    sqlx::query_as(&format!(
        "SELECT d.id, d.app_id, d.status, d.failure_kind, d.pushed_ref, d.commit_sha,
                d.commit_subject, d.instance_id, d.instance_type,
                COALESCE(d.region, cr.region) AS region, d.created_at, d.running_at,
                d.activated_at, d.failed_at, d.error, d.bundle_hash,
                {TLS_AFTER_SWITCH_SQL} AS tls_after_switch,
                d.cleaned_up_at, d.destroyed_at, d.configuration,
                cr.live_deployment_id, cr.public_ip AS stable_ip,
                (cr.app_network->>'scope_tag') IS NOT NULL AS linked
         FROM app_deployments d
         JOIN compute_resources cr ON cr.id = d.app_id
         JOIN organization_members om
              ON om.organization_id = cr.organization_id AND om.user_id = $1
         WHERE cr.lifecycle = $4 AND cr.destroyed_at IS NULL
           AND ($2::uuid IS NULL OR d.app_id = $2)
           AND ($3::uuid IS NULL OR d.id = $3)
           AND (NOT $5::boolean
                OR d.status IN ('reserved', 'building', 'provisioning', 'running', 'destroying')
                OR (d.status = 'failed' AND d.cleaned_up_at IS NULL))
         ORDER BY d.created_at DESC, d.id"
    ))
    .bind(user_id)
    .bind(app_id)
    .bind(deployment_id)
    .bind(LIFECYCLE_DEPLOYMENTS)
    .bind(retained_only)
    .fetch_all(db)
    .await
    .with_context(QueryRowsErrorCtx::database())
}

/// Bounds one EC2 lookup, so a slow answer delays a read by at most this long.
const INSTANCE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The instance's current address from EC2, read in the app's account, or
/// `None` when it has none or EC2 cannot be read: one unreadable instance must
/// not fail the whole read.
async fn current_instance_ip(state: &AppState, row: &DeploymentRow) -> Option<String> {
    let (Some(instance_id), Some(region)) = (row.instance_id.as_deref(), row.region.as_deref())
    else {
        return None;
    };
    let client = match account::app_account(state, row.app_id, region).await {
        Ok(account) => account.ec2(),
        Err(error) => {
            tracing::warn!(deployment_id = %row.id, error = ?error, "failed to resolve the deployment's AWS account");
            return None;
        }
    };
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

/// Caution's hourly price for an instance; none in a linked (BYOC) account,
/// which pays AWS directly.
fn instance_hourly_usd(
    linked: bool,
    instance_type: Option<&str>,
    pricing: &crate::PricingConfig,
) -> Option<f64> {
    if linked {
        return None;
    }
    instance_type
        .and_then(|instance_type| pricing.instance_pricing(instance_type))
        .map(|pricing| pricing.unit_cost_usd())
}

async fn load_views(
    state: &AppState,
    user_id: Uuid,
    app_id: Option<Uuid>,
    deployment_id: Option<Uuid>,
    retained_only: bool,
) -> Result<Vec<DeploymentView>, QueryRowsError> {
    let rows = query_rows_with(&state.db, user_id, app_id, deployment_id, retained_only).await?;
    let addresses = futures::future::join_all(rows.iter().map(|row| async {
        if row.needs_instance_ip() {
            current_instance_ip(state, row).await
        } else {
            None
        }
    }))
    .await;
    Ok(rows
        .into_iter()
        .zip(addresses)
        .map(|(mut row, ip)| {
            row.hourly_usd =
                instance_hourly_usd(row.linked, row.instance_type.as_deref(), &state.pricing);
            row.into_view(ip.as_deref())
        })
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

/// `?retained=1` returns only retained deployments; the default is every row.
#[derive(serde::Deserialize)]
pub(crate) struct ListQuery {
    pub(crate) retained: Option<u8>,
}

pub(crate) async fn list_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(app_id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<DeploymentView>>, ListDeploymentsError> {
    load_views(
        &state,
        auth.user_id,
        Some(app_id),
        None,
        query.retained == Some(1),
    )
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

    load_views(
        &state,
        auth.user_id,
        Some(app_id),
        Some(deployment_id),
        false,
    )
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

    load_views(&state, auth.user_id, None, Some(deployment_id), false)
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
            bundle_hash: None,
            tls_after_switch: false,
            cleaned_up_at: None,
            destroyed_at: None,
            configuration: serde_json::json!({}),
            live_deployment_id,
            stable_ip: Some("198.51.100.42".to_string()),
            linked: false,
            hourly_usd: None,
        }
    }

    #[test]
    fn linked_accounts_get_no_caution_estimate() {
        let pricing = crate::PricingConfig {
            compute_margin_percent: 0.0,
            subscription_tiers: caution_config::pricing::DuplicateCheckedTiers(Default::default()),
            credit_packages: Default::default(),
            paddle_catalog: None,
        };
        assert_eq!(
            instance_hourly_usd(false, Some("m5.xlarge"), &pricing),
            Some(0.192)
        );
        assert_eq!(instance_hourly_usd(true, Some("m5.xlarge"), &pricing), None);
    }

    #[test]
    fn deployment_endpoint_prefers_current_instance_ip() {
        assert_eq!(
            endpoint_ip(
                Role::Live,
                false,
                Some("198.51.100.42"),
                Some("203.0.113.9")
            )
            .as_deref(),
            Some("198.51.100.42")
        );
        // AWS has already released the stable IP of a lost live deployment.
        assert_eq!(
            endpoint_ip(Role::Live, true, Some("198.51.100.42"), None),
            None
        );
        // A candidate's IP changes on stop/start and after a switch away from it.
        assert_eq!(
            endpoint_ip(
                Role::Candidate,
                false,
                Some("198.51.100.42"),
                Some("203.0.113.9")
            )
            .as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            endpoint_ip(Role::Candidate, false, Some("198.51.100.42"), None),
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

    #[test]
    fn view_of_a_lost_live_deployment_has_no_address_and_reports_cleanup() {
        let live = Uuid::new_v4();
        let mut lost = row(live, "failed", Some(live));
        lost.failure_kind = Some("runtime_lost".to_string());
        let view = serde_json::to_value(lost.into_view(None)).unwrap();
        assert_eq!(view["role"], "live");
        assert!(view["public_ip"].is_null());
        assert_eq!(view["cleanup"], "pending");
        let mut cleaned = row(Uuid::new_v4(), "destroyed", Some(live));
        cleaned.cleaned_up_at = Some(Utc::now());
        let view = serde_json::to_value(cleaned.into_view(None)).unwrap();
        assert_eq!(view["cleanup"], "done");
        let view = serde_json::to_value(row(live, "running", Some(live)).into_view(None)).unwrap();
        assert!(view["cleanup"].is_null());
    }

    #[test]
    fn view_carries_retained_cost_and_enclave_size() {
        let id = Uuid::new_v4();
        let mut running = row(id, "running", Some(id));
        running.hourly_usd = Some(0.192);
        running.configuration = serde_json::json!({ "cpus": 2, "memory_mb": 4096 });
        let view = serde_json::to_value(running.into_view(None)).unwrap();
        assert_eq!(view["retained"], true);
        assert_eq!(view["region"], "us-east-1");
        assert_eq!(view["estimated_monthly_usd"], 140.16);
        assert_eq!(
            (
                view["enclave_cpus"].as_u64(),
                view["enclave_memory_mb"].as_u64()
            ),
            (Some(2), Some(4096))
        );
        let mut lost = row(Uuid::new_v4(), "failed", Some(id));
        lost.failure_kind = Some("runtime_lost".to_string());
        lost.hourly_usd = Some(0.192);
        let view = serde_json::to_value(lost.into_view(None)).unwrap();
        assert_eq!(view["retained"], true, "a lost instance keeps its slot");
        assert!(view["estimated_monthly_usd"].is_null(), "and bills nothing");
    }

    #[test]
    fn view_reports_the_recorded_debug_mode() {
        let id = Uuid::new_v4();
        let mut debug = row(id, "running", Some(id));
        debug.configuration = serde_json::json!({ "debug": true });
        let view = serde_json::to_value(debug.into_view(None)).unwrap();
        assert_eq!(view["debug_mode"], true);
        let mut release = row(id, "running", Some(id));
        release.configuration = serde_json::json!({ "debug": false });
        let view = serde_json::to_value(release.into_view(None)).unwrap();
        assert_eq!(view["debug_mode"], false);
        // Not recorded yet (the deployment has not gone Running).
        let view = serde_json::to_value(row(id, "pending", None).into_view(None)).unwrap();
        assert!(view["debug_mode"].is_null());
    }
}

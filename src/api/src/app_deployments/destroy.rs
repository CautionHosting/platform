// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Deployment destruction (`DELETE /resources/{id}/deployments/{deployment_id}`)
//! and the deployment half of app destruction. Deployment destruction never
//! touches the live deployment; only app destruction destroys it.

use super::lifecycle::stop_meter;
use super::{LIFECYCLE_DEPLOYMENTS, PROCESS_ID, admission, lock_app_operations};
use crate::{AppState, AuthContext, deployment, ec2, fully_managed_capacity};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum DestroyPlan {
    Destroy,
    AlreadyDestroyed,
}

#[derive(Debug)]
pub(crate) enum DestroyRejection {
    Live,
    Busy,
}

pub(crate) fn destroy_precondition(
    live: Option<Uuid>,
    target: Uuid,
    status: &str,
) -> Result<DestroyPlan, DestroyRejection> {
    if live == Some(target) {
        return Err(DestroyRejection::Live);
    }
    match status {
        "destroyed" => Ok(DestroyPlan::AlreadyDestroyed),
        "reserved" | "building" | "provisioning" | "destroying" => Err(DestroyRejection::Busy),
        _ => Ok(DestroyPlan::Destroy),
    }
}

/// The app EIP holder and the deployment's OpenTofu state. A seam so the
/// database-backed tests run without AWS or OpenTofu; production uses
/// [`Platform`].
pub(super) trait DestroyBackend {
    /// The instance holding the app Elastic IP.
    async fn address_holder(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError>;

    async fn destroy_state(
        &self,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        region: &str,
    ) -> Result<(), deployment::DestroyDeploymentStateError>;
}

struct Platform;

impl DestroyBackend for Platform {
    async fn address_holder(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError> {
        let credentials = fully_managed_capacity::platform_credentials_for_region(region);
        ec2::Ec2Client::new(&credentials)
            .describe_app_address(&app_id.to_string())
            .await
            .map(|address| address.instance_id)
    }

    async fn destroy_state(
        &self,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        region: &str,
    ) -> Result<(), deployment::DestroyDeploymentStateError> {
        deployment::destroy_deployment_state(org_id, app_id, deployment_id, region).await
    }
}

/// A deployment to destroy, as recorded on its row.
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct DestroyTarget {
    pub(crate) org_id: Uuid,
    pub(crate) app_id: Uuid,
    pub(crate) deployment_id: Uuid,
    pub(crate) instance_id: Option<String>,
    pub(crate) region: Option<String>,
    /// `None` when nothing was provisioned or a cleanup already destroyed it.
    pub(crate) state_key: Option<String>,
}

/// Failure modes for [`complete_destroy`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CompleteDestroyError {
    #[error("failed to destroy the state of deployment {deployment_id} [{location}]")]
    DestroyState {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "database error while recording the destruction of deployment {deployment_id} [{location}]"
    )]
    Database {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Destroys the deployment's state, then records it destroyed and stops its
/// meter. On failure it is left `failed` with `cleaned_up_at` unset: the slot
/// stays counted and the meter running until a retry succeeds. Re-runnable;
/// used by deployment destruction, app destruction and the recovery of
/// `destroying` rows abandoned by a restart.
pub(crate) async fn complete_destroy(
    state: &AppState,
    target: &DestroyTarget,
) -> Result<(), CompleteDestroyError> {
    complete_destroy_with(state, &Platform, target).await
}

pub(super) async fn complete_destroy_with(
    state: &AppState,
    backend: &impl DestroyBackend,
    target: &DestroyTarget,
) -> Result<(), CompleteDestroyError> {
    use CompleteDestroyErrorCtx as Ctx;

    let id = target.deployment_id;
    // `mark_provisioning` records the state key and region together.
    let destroyed = match (&target.state_key, &target.region) {
        (Some(_), Some(region)) => {
            backend
                .destroy_state(target.org_id, target.app_id, id, region)
                .await
        }
        _ => Ok(()), // nothing left to destroy
    };
    if let Err(error) = destroyed {
        // Never reverts a row a concurrent destroy already finished.
        sqlx::query(
            "UPDATE app_deployments
             SET status = 'failed', failure_kind = COALESCE(failure_kind, 'provisioning'),
                 cleaned_up_at = NULL, error = 'destroy failed; retry'
             WHERE id = $1 AND app_id = $2 AND status <> 'destroyed'",
        )
        .bind(id)
        .bind(target.app_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::database(id))?;
        return Err(error).with_context(Ctx::destroy_state(id));
    }
    sqlx::query(
        "UPDATE app_deployments
         SET status = 'destroyed', destroyed_at = NOW(), cleaned_up_at = NOW()
         WHERE id = $1 AND app_id = $2",
    )
    .bind(id)
    .bind(target.app_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::database(id))?;
    if let Some(instance_id) = target.instance_id.as_deref() {
        stop_meter(state, instance_id).await;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyError {
    #[error("deployment not found [{location}]")]
    NotFound { location: Location },
    #[error("destroy rejected: {rejection:?} [{location}]")]
    Rejected {
        rejection: DestroyRejection,
        location: Location,
    },
    #[error("deployment holds the app Elastic IP [{location}]")]
    HoldsAddress { location: Location },
    #[error("AWS error while reading the app Elastic IP [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("database error while destroying a deployment [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("deployment destroy failed [{location}]")]
    DestroyFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DestroyError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "Deployment not found."),
            Self::Rejected {
                rejection: DestroyRejection::Live,
                ..
            } => (
                StatusCode::CONFLICT,
                "The live deployment cannot be destroyed; switch to another deployment first.",
            ),
            Self::Rejected {
                rejection: DestroyRejection::Busy,
                ..
            } => (
                StatusCode::CONFLICT,
                "This deployment is being built, provisioned or destroyed; retry shortly.",
            ),
            Self::HoldsAddress { .. } => (
                StatusCode::CONFLICT,
                "This deployment currently holds the app address; wait for reconciliation or switch first.",
            ),
            Self::Aws { .. } | Self::Database { .. } | Self::DestroyFailed { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Deployment destroy failed; retry.",
            ),
        };
        tracing::warn!(error = %self, "deployment destroy failed");
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[derive(sqlx::FromRow)]
struct DestroyRow {
    live_deployment_id: Option<Uuid>,
    region: Option<String>,
    status: String,
    instance_id: Option<String>,
}

pub(crate) async fn destroy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((app_id, deployment_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, DestroyError> {
    use DestroyErrorCtx as Ctx;

    let Some(target) =
        begin_destroy(&state.db, &Platform, auth.user_id, app_id, deployment_id).await?
    else {
        return Ok(StatusCode::NO_CONTENT);
    };
    // Its own task: a dropped request must not strand the row in `destroying`.
    let task_state = state.clone();
    tokio::spawn(async move { complete_destroy(&task_state, &target).await })
        .await
        .with_context(Ctx::destroy_failed())?
        .with_context(Ctx::destroy_failed())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Under the app lock: refuses the live deployment, an active operation and
/// the Elastic IP holder, then marks the target `destroying` for this process.
/// `None`: already destroyed.
pub(super) async fn begin_destroy(
    db: &PgPool,
    backend: &impl DestroyBackend,
    user_id: Uuid,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<DestroyTarget>, DestroyError> {
    use DestroyErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::database())?;
    // Membership join as in the switch.
    let row: Option<DestroyRow> = sqlx::query_as(
        "SELECT cr.live_deployment_id, COALESCE(cr.region, d.region) AS region,
                d.status, d.instance_id
         FROM compute_resources cr
         JOIN organization_members om ON om.organization_id = cr.organization_id AND om.user_id = $3
         JOIN app_deployments d ON d.app_id = cr.id AND d.id = $2
         WHERE cr.id = $1 AND cr.lifecycle = $4 AND cr.destroyed_at IS NULL
         FOR UPDATE OF cr, d",
    )
    .bind(app_id)
    .bind(deployment_id)
    .bind(user_id)
    .bind(LIFECYCLE_DEPLOYMENTS)
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    let Some(row) = row else {
        return Err(DestroyError::NotFound {
            location: std::panic::Location::caller(),
        });
    };
    match destroy_precondition(row.live_deployment_id, deployment_id, &row.status) {
        Ok(DestroyPlan::Destroy) => {}
        Ok(DestroyPlan::AlreadyDestroyed) => return Ok(None),
        Err(rejection) => {
            return Err(DestroyError::Rejected {
                rejection,
                location: std::panic::Location::caller(),
            });
        }
    }
    if let Some(instance_id) = row.instance_id.as_deref() {
        // After an interrupted switch the pointer can lag the association,
        // which is the source of truth. The region is recorded before the
        // instance, so it is always known here.
        let Some(region) = row.region.as_deref() else {
            return Err(DestroyError::NotFound {
                location: std::panic::Location::caller(),
            });
        };
        let holder = backend
            .address_holder(app_id, region)
            .await
            .with_context(Ctx::aws())?;
        if holder.as_deref() == Some(instance_id) {
            return Err(DestroyError::HoldsAddress {
                location: std::panic::Location::caller(),
            });
        }
    }
    let target: DestroyTarget = sqlx::query_as(
        "UPDATE app_deployments SET status = 'destroying', owner_process_id = $2
         WHERE id = $1
         RETURNING organization_id AS org_id, app_id, id AS deployment_id, instance_id, region,
                   CASE WHEN cleaned_up_at IS NULL THEN state_key END AS state_key",
    )
    .bind(deployment_id)
    .bind(*PROCESS_ID)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;
    Ok(Some(target))
}

/// Failure modes for [`destroy_all_for_app`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyAllError {
    #[error(
        "deployment {deployment_id} of app {app_id} is still building or provisioning [{location}]"
    )]
    Busy {
        app_id: Uuid,
        deployment_id: Uuid,
        location: Location,
    },
    #[error("database error while destroying the deployments of app {app_id} [{location}]")]
    Database {
        app_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to destroy deployment {deployment_id} of app {app_id} [{location}]")]
    Destroy {
        app_id: Uuid,
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(sqlx::FromRow)]
struct TeardownRow {
    id: Uuid,
    status: String,
    owner_process_id: Option<Uuid>,
    instance_id: Option<String>,
    region: Option<String>,
    state_key: Option<String>,
}

/// App destruction: destroys every deployment, the live one included, before
/// the app state. Attempts all of them and returns the first error.
pub(crate) async fn destroy_all_for_app(
    state: &AppState,
    org_id: Uuid,
    app_id: Uuid,
) -> Result<(), DestroyAllError> {
    destroy_all_for_app_with(state, &Platform, org_id, app_id).await
}

pub(super) async fn destroy_all_for_app_with(
    state: &AppState,
    backend: &impl DestroyBackend,
    org_id: Uuid,
    app_id: Uuid,
) -> Result<(), DestroyAllError> {
    use DestroyAllErrorCtx as Ctx;

    // A cleaned-up failure has no state left to destroy.
    let rows: Vec<TeardownRow> = sqlx::query_as(
        "SELECT id, status, owner_process_id, instance_id, region,
                CASE WHEN cleaned_up_at IS NULL THEN state_key END AS state_key
         FROM app_deployments
         WHERE app_id = $1 AND status <> 'destroyed'
         ORDER BY created_at",
    )
    .bind(app_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::database(app_id))?;

    let mut first_error = None;
    for row in rows {
        let deployment_id = row.id;
        let result = match row.status.as_str() {
            // Unreachable behind the termination guard; never destroy a
            // state under a running OpenTofu.
            "building" | "provisioning" if row.owner_process_id == Some(*PROCESS_ID) => {
                Err(DestroyAllError::Busy {
                    app_id,
                    deployment_id,
                    location: std::panic::Location::caller(),
                })
            }
            "reserved" => admission::release_reservation(&state.db, deployment_id, Some(app_id))
                .await
                .with_context(Ctx::database(app_id)),
            _ => {
                let target = DestroyTarget {
                    org_id,
                    app_id,
                    deployment_id,
                    instance_id: row.instance_id,
                    region: row.region,
                    state_key: row.state_key,
                };
                complete_destroy_with(state, backend, &target)
                    .await
                    .with_context(Ctx::destroy(app_id, deployment_id))
            }
        };
        if let Err(error) = result {
            tracing::warn!(error = %error, "app teardown could not destroy a deployment");
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Stops the meter of every deployment not recorded destroyed. For a forced
/// app delete, after which nothing else would stop them.
pub(crate) async fn stop_remaining_meters(state: &AppState, app_id: Uuid) {
    let instances: Vec<String> = match sqlx::query_scalar(
        "SELECT instance_id FROM app_deployments
         WHERE app_id = $1 AND status <> 'destroyed' AND instance_id IS NOT NULL",
    )
    .bind(app_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(instances) => instances,
        Err(error) => {
            tracing::error!(app_id = %app_id, error = %error, "failed to list deployment meters to stop");
            return;
        }
    };
    for instance_id in instances {
        stop_meter(state, &instance_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_deployment_is_never_destroyed() {
        let live = Uuid::new_v4();
        assert!(matches!(
            destroy_precondition(Some(live), live, "running"),
            Err(DestroyRejection::Live)
        ));
        assert!(matches!(
            destroy_precondition(Some(live), live, "failed"),
            Err(DestroyRejection::Live)
        ));
    }

    #[test]
    fn active_operations_are_busy_and_destroyed_is_idempotent() {
        let (live, target) = (Uuid::new_v4(), Uuid::new_v4());
        for status in ["reserved", "building", "provisioning", "destroying"] {
            assert!(
                matches!(
                    destroy_precondition(Some(live), target, status),
                    Err(DestroyRejection::Busy)
                ),
                "{status}"
            );
        }
        assert!(matches!(
            destroy_precondition(Some(live), target, "destroyed"),
            Ok(DestroyPlan::AlreadyDestroyed)
        ));
        assert!(matches!(
            destroy_precondition(Some(live), target, "running"),
            Ok(DestroyPlan::Destroy)
        ));
        assert!(matches!(
            destroy_precondition(None, target, "failed"),
            Ok(DestroyPlan::Destroy)
        ));
    }
}

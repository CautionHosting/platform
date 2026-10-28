// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Deployment destruction (`DELETE /resources/{id}/deployments/{deployment_id}`)
//! and the deployment half of app destruction. Deployment destruction never
//! touches the live deployment; only app destruction destroys it.

use super::account::{self, AppAccount};
use super::events;
use super::lifecycle::stop_meter;
use super::{LIFECYCLE_DEPLOYMENTS, PROCESS_ID, admission, lock_app_operations};
use crate::{AppState, AuthContext, deployment, ec2};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use caution_error::Note;
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::collections::HashMap;
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
    /// App destroy is running: a second `tofu destroy` would share its state.
    Terminating,
}

impl std::fmt::Display for DestroyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Live => {
                "The live deployment cannot be destroyed; switch to another deployment first."
            }
            Self::Busy => {
                "This deployment is being built, provisioned or destroyed; retry shortly."
            }
            Self::Terminating => "The app is being destroyed.",
        })
    }
}

/// Actionable guidance for a rejection; empty when the message already says it.
fn rejection_notes(rejection: &DestroyRejection) -> Vec<Note> {
    match rejection {
        DestroyRejection::Live => vec![Note::from(
            "Switch another deployment to live, then retry the destroy: `caution apps switch <deployment>`.",
        )],
        DestroyRejection::Busy | DestroyRejection::Terminating => Vec::new(),
    }
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

/// The app EIP holder, the deployment's OpenTofu state and its lock, and the
/// EC2 resources tagged with the deployment. A seam so the database-backed
/// tests run without AWS or OpenTofu; production uses [`Platform`].
pub(super) trait DestroyBackend {
    /// The account the app's deployments live in ([`account::app_account`]).
    async fn app_account(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<AppAccount, account::AppAccountError>;

    /// The instance holding the app Elastic IP.
    async fn address_holder(
        &self,
        app_id: Uuid,
        account: &AppAccount,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError>;

    async fn destroy_state(
        &self,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<(), deployment::DestroyDeploymentStateError>;

    /// Deletes a state lock left by an OpenTofu run that died with its process.
    async fn clear_state_lock(
        &self,
        state_key: &str,
    ) -> Result<(), deployment::ClearStateLockError>;

    /// Instances not yet terminated that EC2 lists as tagged with the app and
    /// the deployment. [`sweep_leftovers`] checks both tags again.
    async fn tagged_instances(
        &self,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<Vec<ec2::Instance>, ec2::DescribeInstancesError>;

    async fn terminate_instances(
        &self,
        account: &AppAccount,
        instance_ids: &[String],
    ) -> Result<(), ec2::TerminateInstancesError>;

    /// Security groups EC2 lists as tagged with the app and the deployment.
    async fn tagged_security_groups(
        &self,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<Vec<ec2::SecurityGroup>, ec2::DescribeSecurityGroupsError>;

    async fn delete_security_group(
        &self,
        account: &AppAccount,
        group_id: &str,
    ) -> Result<(), ec2::DeleteSecurityGroupError>;
}

/// Production: EC2 and OpenTofu in the app's account.
pub(super) struct Platform<'a>(pub(super) &'a AppState);

/// The EC2 filters selecting what OpenTofu tags with the app and the deployment.
fn deployment_tag_filters(app_id: Uuid, deployment_id: Uuid) -> Vec<ec2::Filter> {
    vec![
        ec2::Filter::new(&format!("tag:{RESOURCE_ID_TAG}"), &[&app_id.to_string()]),
        ec2::Filter::new(
            &format!("tag:{DEPLOYMENT_ID_TAG}"),
            &[&deployment_id.to_string()],
        ),
    ]
}

impl DestroyBackend for Platform<'_> {
    async fn app_account(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<AppAccount, account::AppAccountError> {
        account::app_account(self.0, app_id, region).await
    }

    async fn address_holder(
        &self,
        app_id: Uuid,
        account: &AppAccount,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError> {
        account
            .ec2()
            .describe_app_address(&app_id.to_string())
            .await
            .map(|address| address.instance_id)
    }

    async fn destroy_state(
        &self,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<(), deployment::DestroyDeploymentStateError> {
        deployment::destroy_deployment_state(
            org_id,
            app_id,
            deployment_id,
            account.region(),
            account.provider_credentials(),
        )
        .await
    }

    async fn clear_state_lock(
        &self,
        state_key: &str,
    ) -> Result<(), deployment::ClearStateLockError> {
        deployment::clear_state_lock(state_key).await
    }

    async fn tagged_instances(
        &self,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<Vec<ec2::Instance>, ec2::DescribeInstancesError> {
        let mut filters = deployment_tag_filters(app_id, deployment_id);
        filters.push(ec2::Filter::new(
            "instance-state-name",
            &["pending", "running", "shutting-down", "stopping", "stopped"],
        ));
        account.ec2().describe_instances(&filters).await
    }

    async fn terminate_instances(
        &self,
        account: &AppAccount,
        instance_ids: &[String],
    ) -> Result<(), ec2::TerminateInstancesError> {
        account.ec2().terminate_instances(instance_ids).await
    }

    async fn tagged_security_groups(
        &self,
        app_id: Uuid,
        deployment_id: Uuid,
        account: &AppAccount,
    ) -> Result<Vec<ec2::SecurityGroup>, ec2::DescribeSecurityGroupsError> {
        account
            .ec2()
            .describe_security_groups(&deployment_tag_filters(app_id, deployment_id))
            .await
    }

    async fn delete_security_group(
        &self,
        account: &AppAccount,
        group_id: &str,
    ) -> Result<(), ec2::DeleteSecurityGroupError> {
        account.ec2().delete_security_group(group_id).await
    }
}

/// The tags `generate_deployment_main_tf` puts on a deployment's instance and
/// security group.
const RESOURCE_ID_TAG: &str = "ResourceId";
const DEPLOYMENT_ID_TAG: &str = "DeploymentId";

/// Whether `tags` name both the app and the deployment.
fn tagged_for(tags: &HashMap<String, String>, app_id: Uuid, deployment_id: Uuid) -> bool {
    tags.get(RESOURCE_ID_TAG) == Some(&app_id.to_string())
        && tags.get(DEPLOYMENT_ID_TAG) == Some(&deployment_id.to_string())
}

/// The instances a sweep of `deployment_id` terminates: only those tagged with
/// both the app and the deployment, and never one of `live`.
fn leftover_instances(
    instances: &[ec2::Instance],
    app_id: Uuid,
    deployment_id: Uuid,
    live: &[String],
) -> Vec<String> {
    instances
        .iter()
        .filter(|instance| tagged_for(&instance.tags, app_id, deployment_id))
        .filter(|instance| !live.contains(&instance.instance_id))
        .map(|instance| instance.instance_id.clone())
        .collect()
}

/// Failure modes for [`sweep_leftovers`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SweepLeftoversError {
    #[error("failed to read the live instance of app {app_id} [{location}]")]
    Database {
        app_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to list the instances of deployment {deployment_id} [{location}]")]
    DescribeInstances {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "failed to terminate the leftover instances of deployment {deployment_id} [{location}]"
    )]
    TerminateInstances {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "leftover instances {instance_ids:?} of deployment {deployment_id} are terminating [{location}]"
    )]
    Terminating {
        deployment_id: Uuid,
        instance_ids: Vec<String>,
        location: Location,
    },
}

/// Removes what the deployment's OpenTofu state may have missed: OpenTofu
/// persists state on an interval, so an API restart during `tofu apply` can
/// leave an instance or security group that `tofu destroy` cannot see. Touches
/// only resources tagged with both the app and the deployment, and never the
/// live instance. `Ok` once no such instance remains; until then it fails
/// with `Terminating` and a later pass retries. Security groups are best
/// effort: one still used by a terminating instance is refused and retried
/// with it.
pub(super) async fn sweep_leftovers(
    db: &PgPool,
    backend: &impl DestroyBackend,
    app_id: Uuid,
    deployment_id: Uuid,
    account: &AppAccount,
) -> Result<(), SweepLeftoversError> {
    use SweepLeftoversErrorCtx as Ctx;

    let live: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT cr.provider_resource_id, d.instance_id
         FROM compute_resources cr LEFT JOIN app_deployments d ON d.id = cr.live_deployment_id
         WHERE cr.id = $1",
    )
    .bind(app_id)
    .fetch_optional(db)
    .await
    .with_context(Ctx::database(app_id))?;
    let live: Vec<String> = live
        .into_iter()
        .flat_map(|(app_instance, live_instance)| [app_instance, live_instance])
        .flatten()
        .collect();

    let instances = backend
        .tagged_instances(app_id, deployment_id, account)
        .await
        .with_context(Ctx::describe_instances(deployment_id))?;
    let leftovers = leftover_instances(&instances, app_id, deployment_id, &live);
    if !leftovers.is_empty() {
        tracing::warn!(deployment_id = %deployment_id, instance_ids = ?leftovers, "terminating deployment instances its state missed");
        backend
            .terminate_instances(account, &leftovers)
            .await
            .with_context(Ctx::terminate_instances(deployment_id))?;
    }

    match backend
        .tagged_security_groups(app_id, deployment_id, account)
        .await
    {
        Ok(groups) => {
            for group in groups
                .iter()
                .filter(|group| tagged_for(&group.tags, app_id, deployment_id))
            {
                if let Err(error) = backend
                    .delete_security_group(account, &group.group_id)
                    .await
                {
                    tracing::info!(deployment_id = %deployment_id, group_id = %group.group_id, error = %error, "leftover security group not deleted; retried while its deployment is cleaned up");
                }
            }
        }
        Err(error) => {
            tracing::warn!(deployment_id = %deployment_id, error = %error, "failed to list leftover security groups");
        }
    }

    if leftovers.is_empty() {
        Ok(())
    } else {
        Err(SweepLeftoversError::Terminating {
            deployment_id,
            instance_ids: leftovers,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`destroy_and_sweep`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyAndSweepError {
    #[error("failed to resolve the AWS account of deployment {deployment_id} [{location}]")]
    Account {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to destroy the state of deployment {deployment_id} [{location}]")]
    DestroyState {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to sweep the leftovers of deployment {deployment_id} [{location}]")]
    Sweep {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Destroys the deployment's state, then sweeps its leftovers. `Ok` only once
/// nothing tagged with it remains: only then may its cleanup be recorded and
/// its meter stopped.
pub(super) async fn destroy_and_sweep(
    db: &PgPool,
    backend: &impl DestroyBackend,
    org_id: Uuid,
    app_id: Uuid,
    deployment_id: Uuid,
    region: &str,
) -> Result<(), DestroyAndSweepError> {
    use DestroyAndSweepErrorCtx as Ctx;

    let account = backend
        .app_account(app_id, region)
        .await
        .with_context(Ctx::account(deployment_id))?;
    backend
        .destroy_state(org_id, app_id, deployment_id, &account)
        .await
        .with_context(Ctx::destroy_state(deployment_id))?;
    sweep_leftovers(db, backend, app_id, deployment_id, &account)
        .await
        .with_context(Ctx::sweep(deployment_id))
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
    #[error("failed to destroy deployment {deployment_id} [{location}]")]
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

/// Destroys the deployment's state and sweeps its leftovers, then records it
/// destroyed and stops its meter. On failure, or while a leftover instance is
/// still terminating, it is left `failed` with `cleaned_up_at` unset: the slot
/// stays counted and the meter running until a retry succeeds. Re-runnable;
/// used by deployment destruction, app destruction and the recovery of
/// `destroying` rows abandoned by a restart.
pub(crate) async fn complete_destroy(
    state: &AppState,
    target: &DestroyTarget,
) -> Result<(), CompleteDestroyError> {
    complete_destroy_with(state, &Platform(state), target).await
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
            destroy_and_sweep(&state.db, backend, target.org_id, target.app_id, id, region).await
        }
        _ => Ok(()), // nothing left to destroy
    };
    if let Err(error) = destroyed {
        // Never reverts a row a concurrent destroy already finished.
        sqlx::query(
            "UPDATE app_deployments
             SET status = 'failed', failure_kind = 'provisioning',
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

#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum DestroyError {
    #[error("Deployment not found.")]
    NotFound {
        #[provide]
        location: Location,
    },
    #[error("{rejection}")]
    Rejected {
        rejection: DestroyRejection,
        #[provide(ref = [caution_error::Note])]
        notes: Vec<Note>,
        #[provide]
        location: Location,
    },
    #[error(
        "This deployment currently holds the app address; wait for reconciliation or switch first."
    )]
    HoldsAddress {
        #[provide]
        location: Location,
    },
    #[error("Deployment destroy failed; retry.")]
    Aws {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Deployment destroy failed; retry.")]
    Database {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Deployment destroy failed; retry.")]
    DestroyFailed {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl DestroyError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Rejected { .. } | Self::HoldsAddress { .. } => StatusCode::CONFLICT,
            Self::Aws { .. } | Self::Database { .. } | Self::DestroyFailed { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for DestroyError {
    fn into_response(self) -> Response {
        let status = self.status();
        tracing::warn!(error = ?self, "deployment destroy failed");
        let report = caution_error::ErrorReport::from_error(&self);
        sentry_middleware::error_response_provider(status, Json(report), self)
    }
}

#[derive(sqlx::FromRow)]
struct DestroyRow {
    live_deployment_id: Option<Uuid>,
    region: Option<String>,
    status: String,
    instance_id: Option<String>,
    app_state: String,
}

pub(crate) async fn destroy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((app_id, deployment_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, DestroyError> {
    use DestroyErrorCtx as Ctx;

    // Its own task from the first write: a dropped request must not strand
    // the row in `destroying` nor leave its operation unanswered.
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let Some((target, operation_id)) = begin_destroy(
            &task_state.db,
            &Platform(&task_state),
            &auth,
            app_id,
            deployment_id,
        )
        .await?
        else {
            return Ok(());
        };
        let destroyed = complete_destroy(&task_state, &target).await;
        if destroyed.as_ref().is_err_and(leaves_row_destroying) {
            fail_destroying(&task_state.db, deployment_id).await;
        }
        let (outcome, error) = match &destroyed {
            Ok(()) => (events::Outcome::Succeeded, None),
            Err(_) => (
                events::Outcome::Failed,
                Some("Deployment destroy failed; cleanup is retried automatically."),
            ),
        };
        events::finish(&task_state.db, operation_id, outcome, error).await;
        destroyed.with_context(Ctx::destroy_failed())
    });
    match task.await {
        Ok(destroyed) => destroyed.map(|()| StatusCode::NO_CONTENT),
        Err(error) => {
            fail_destroying(&state.db, deployment_id).await;
            Err(error).with_context(Ctx::destroy_failed())
        }
    }
}

/// Only a lost write leaves the row `destroying`. A `DestroyState` error
/// already marked it `failed`, and flipping it again could hit the fresh
/// `destroying` row of a concurrent `destroy -d` retry.
fn leaves_row_destroying(error: &CompleteDestroyError) -> bool {
    matches!(error, CompleteDestroyError::Database { .. })
}

/// Best effort, after a failed or panicked deployment destroy: a row this
/// process still holds in `destroying` (its last write failed) becomes
/// `failed` and awaits cleanup, which reconciliation retries. A settled row is
/// left alone.
async fn fail_destroying(db: &PgPool, deployment_id: Uuid) {
    if let Err(error) = sqlx::query(
        "UPDATE app_deployments
         SET status = 'failed', failure_kind = 'provisioning',
             cleaned_up_at = NULL, error = 'destroy failed; retry'
         WHERE id = $1 AND owner_process_id = $2 AND status = 'destroying'",
    )
    .bind(deployment_id)
    .bind(*PROCESS_ID)
    .execute(db)
    .await
    {
        tracing::error!(deployment_id = %deployment_id, error = %error, "failed to record a failed deployment destroy; reconciliation re-runs it");
    }
}

/// Under the app lock: refuses the live deployment, an active operation and
/// the Elastic IP holder, then marks the target `destroying` for this process
/// and records the operation in the same transaction. `None`: already
/// destroyed (nothing recorded).
pub(super) async fn begin_destroy(
    db: &PgPool,
    backend: &impl DestroyBackend,
    actor: &AuthContext,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<Option<(DestroyTarget, Uuid)>, DestroyError> {
    use DestroyErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::database())?;
    // Membership join as in the switch.
    let row: Option<DestroyRow> = sqlx::query_as(
        "SELECT cr.live_deployment_id, COALESCE(cr.region, d.region) AS region,
                d.status, d.instance_id, cr.state::text AS app_state
         FROM compute_resources cr
         JOIN organization_members om ON om.organization_id = cr.organization_id AND om.user_id = $3
         JOIN app_deployments d ON d.app_id = cr.id AND d.id = $2
         WHERE cr.id = $1 AND cr.lifecycle = $4 AND cr.destroyed_at IS NULL
         FOR UPDATE OF cr, d",
    )
    .bind(app_id)
    .bind(deployment_id)
    .bind(actor.user_id)
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
        Ok(DestroyPlan::Destroy) if row.app_state == "terminating" => {
            return Err(DestroyError::Rejected {
                rejection: DestroyRejection::Terminating,
                notes: rejection_notes(&DestroyRejection::Terminating),
                location: std::panic::Location::caller(),
            });
        }
        Ok(DestroyPlan::Destroy) => {}
        Ok(DestroyPlan::AlreadyDestroyed) => return Ok(None),
        Err(rejection) => {
            return Err(DestroyError::Rejected {
                notes: rejection_notes(&rejection),
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
        let account = backend
            .app_account(app_id, region)
            .await
            .with_context(Ctx::aws())?;
        let holder = backend
            .address_holder(app_id, &account)
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
    let operation_id = events::begin(
        &mut *tx,
        events::NewOperation {
            org_id: target.org_id,
            app_id,
            operation: events::Operation::DeploymentDestroy,
            actor,
            previous_deployment_id: None,
            target_deployment_id: Some(deployment_id),
            signed_request_id: None,
        },
    )
    .await
    .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;
    Ok(Some((target, operation_id)))
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
    #[error(
        "failed to clear the stale state lock of deployment {deployment_id} of app {app_id} [{location}]"
    )]
    ClearStateLock {
        app_id: Uuid,
        deployment_id: Uuid,
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
    destroy_all_for_app_with(state, &Platform(state), org_id, app_id).await
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
                // The caller holds the teardown lock and the API is a single
                // process: another owner died with its OpenTofu, so any lock
                // it left is stale. Reconciliation never unlocks a lost
                // runtime, whose stale lock would fail every retry.
                let unlocked = match target.state_key.as_deref() {
                    Some(state_key) if row.owner_process_id != Some(*PROCESS_ID) => backend
                        .clear_state_lock(state_key)
                        .await
                        .with_context(Ctx::clear_state_lock(app_id, deployment_id)),
                    _ => Ok(()),
                };
                match unlocked {
                    Ok(()) => complete_destroy_with(state, backend, &target)
                        .await
                        .with_context(Ctx::destroy(app_id, deployment_id)),
                    Err(error) => Err(error),
                }
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
    fn live_rejection_carries_an_actionable_note() {
        use axum::response::IntoResponse;
        use sentry_middleware::SentryReportable;

        let error = DestroyError::Rejected {
            rejection: DestroyRejection::Live,
            notes: rejection_notes(&DestroyRejection::Live),
            location: std::panic::Location::caller(),
        };

        let report = caution_error::ErrorReport::from_error(&error);
        assert_eq!(
            report.error,
            "The live deployment cannot be destroyed; switch to another deployment first."
        );
        assert_eq!(report.errors[0].notes.len(), 1);
        assert!(report.errors[0].notes[0].0.contains("caution apps switch"));
        assert!(
            !report.errors[0].error.contains(".rs:"),
            "no call site leaks"
        );
        assert!(
            caution_error::location(&error).is_some(),
            "location provided"
        );

        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.extensions().get::<SentryReportable>().is_some());

        let busy = DestroyError::Rejected {
            rejection: DestroyRejection::Busy,
            notes: rejection_notes(&DestroyRejection::Busy),
            location: std::panic::Location::caller(),
        };
        assert!(
            caution_error::ErrorReport::from_error(&busy).errors[0]
                .notes
                .is_empty()
        );
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

    #[test]
    fn only_a_lost_write_leaves_the_row_destroying() {
        let deployment_id = Uuid::new_v4();
        let location = std::panic::Location::caller();
        let source = || BoxError::from("failed");
        assert!(leaves_row_destroying(&CompleteDestroyError::Database {
            deployment_id,
            location,
            source: source(),
        }));
        assert!(!leaves_row_destroying(
            &CompleteDestroyError::DestroyState {
                deployment_id,
                location,
                source: source(),
            }
        ));
    }

    #[test]
    fn sweep_takes_only_instances_tagged_with_both_and_never_the_live_one() {
        let (app, deployment) = (Uuid::new_v4(), Uuid::new_v4());
        let (app_tag, deployment_tag) = (app.to_string(), deployment.to_string());
        let other = Uuid::new_v4().to_string();
        let instance = |id: &str, tags: &[(&str, &str)]| ec2::Instance {
            instance_id: id.to_string(),
            instance_type: None,
            tags: tags
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        };
        let both = [
            ("ResourceId", app_tag.as_str()),
            ("DeploymentId", deployment_tag.as_str()),
        ];
        let instances = [
            instance("i-leftover", &both),
            instance("i-live", &both),
            instance("i-deployment-only", &[("DeploymentId", &deployment_tag)]),
            instance("i-app-only", &[("ResourceId", &app_tag)]),
            instance(
                "i-other-app",
                &[("ResourceId", &other), ("DeploymentId", &deployment_tag)],
            ),
            instance(
                "i-other-deployment",
                &[("ResourceId", &app_tag), ("DeploymentId", &other)],
            ),
            instance("i-untagged", &[]),
        ];
        assert_eq!(
            leftover_instances(&instances, app, deployment, &["i-live".to_string()]),
            vec!["i-leftover".to_string()]
        );
    }
}

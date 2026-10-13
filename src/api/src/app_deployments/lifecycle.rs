// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Candidate deployment lifecycle: provisioning bookkeeping, Running and
//! auto-activation, and scoped failure cleanup.

use super::{PROCESS_ID, admission, lock_app_operations};
use crate::{AppState, deployment, ec2, fully_managed_capacity, managed_dns};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::atomic::{AtomicU8, Ordering};
use uuid::Uuid;

#[cfg(test)]
mod db_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Live,
    Candidate,
}

impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Live => "live",
            Role::Candidate => "candidate",
        }
    }
}

/// Auto-activation rule: a deployment becomes live only when nothing is live.
pub(crate) fn activates_on_running(live_deployment_id: Option<Uuid>) -> bool {
    live_deployment_id.is_none()
}

/// Display role: only the deployment the live pointer names is live.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "first caller lands with the deployments listing")
)]
pub(crate) fn role_for(live_deployment_id: Option<Uuid>, deployment_id: Uuid) -> Role {
    if live_deployment_id == Some(deployment_id) {
        Role::Live
    } else {
        Role::Candidate
    }
}

pub(crate) struct RunningDeployment {
    pub(crate) id: Uuid,
    pub(crate) instance_id: String,
    pub(crate) instance_type: Option<String>,
    pub(crate) region: String,
    pub(crate) configuration: serde_json::Value,
}

pub(crate) struct Activation {
    pub(crate) role: Role,
    pub(crate) live_deployment_id: Option<Uuid>,
    pub(crate) dns: Option<managed_dns::DnsSnapshot>,
    pub(crate) eip_public_ip: Option<String>,
}

/// Failure modes for [`mark_provisioning`] and [`record_instance`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum MarkProvisioningError {
    #[error("deployment {deployment_id} is no longer owned by this process [{location}]")]
    OwnershipLost {
        deployment_id: Uuid,
        location: Location,
    },
    #[error("database error while updating deployment {deployment_id} [{location}]")]
    Database {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

pub(crate) async fn mark_provisioning(
    db: &PgPool,
    deployment_id: Uuid,
    state_key: &str,
    region: &str,
    eif_s3_key: &str,
) -> Result<(), MarkProvisioningError> {
    let updated = sqlx::query(
        "UPDATE app_deployments
         SET status = 'provisioning', state_key = $2, region = $3, eif_s3_key = $4
         WHERE id = $1 AND owner_process_id = $5 AND status = 'building'",
    )
    .bind(deployment_id)
    .bind(state_key)
    .bind(region)
    .bind(eif_s3_key)
    .bind(*PROCESS_ID)
    .execute(db)
    .await
    .with_context(MarkProvisioningErrorCtx::database(deployment_id))?;
    if updated.rows_affected() == 0 {
        return Err(MarkProvisioningError::OwnershipLost {
            deployment_id,
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

/// Persists the instance right after `tofu apply`, before metering, so every
/// later failure path can find, clean up and stop the meter of this instance.
pub(crate) async fn record_instance(
    db: &PgPool,
    deployment_id: Uuid,
    instance_id: &str,
    instance_type: Option<&str>,
) -> Result<(), MarkProvisioningError> {
    let updated = sqlx::query(
        "UPDATE app_deployments SET instance_id = $2, instance_type = $3
         WHERE id = $1 AND owner_process_id = $4 AND status = 'provisioning'",
    )
    .bind(deployment_id)
    .bind(instance_id)
    .bind(instance_type)
    .bind(*PROCESS_ID)
    .execute(db)
    .await
    .with_context(MarkProvisioningErrorCtx::database(deployment_id))?;
    if updated.rows_affected() == 0 {
        return Err(MarkProvisioningError::OwnershipLost {
            deployment_id,
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

/// Failure modes for [`complete_running`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CompleteRunningError {
    #[error("deployment {deployment_id} is no longer owned by this process [{location}]")]
    OwnershipLost {
        deployment_id: Uuid,
        location: Location,
    },
    #[error("app {app_id} became {state} during the deployment [{location}]")]
    AppNotActive {
        app_id: Uuid,
        state: String,
        location: Location,
    },
    #[error("failed to lock app operations [{location}]")]
    Lock {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to attach the app Elastic IP [{location}]")]
    AttachAddress {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("database error while completing a deployment [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Reads and moves the app Elastic IP. A seam so the database-backed tests can
/// pause or fail the EC2 calls; production uses [`ec2::Ec2Client`].
pub(super) trait AppAddressMover {
    async fn move_address(
        &self,
        resource_id: &str,
        target: &str,
        expected_holder: Option<&str>,
    ) -> Result<String, ec2::MoveAppAddressError>;

    async fn describe_address(
        &self,
        resource_id: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError>;
}

impl AppAddressMover for ec2::Ec2Client {
    async fn move_address(
        &self,
        resource_id: &str,
        target: &str,
        expected_holder: Option<&str>,
    ) -> Result<String, ec2::MoveAppAddressError> {
        self.move_app_address(resource_id, target, expected_holder)
            .await
    }

    async fn describe_address(
        &self,
        resource_id: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
        self.describe_app_address(resource_id).await
    }
}

/// Failure modes for [`project_live`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to record deployment {deployment_id} live for app {app_id} [{location}]")]
pub(crate) struct ProjectLiveError {
    app_id: Uuid,
    deployment_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// Makes `deployment_id` live and refreshes the app-level projection from it:
/// `provider_resource_id`, `state`, `public_ip` (= the app EIP), `region`,
/// `configuration` and managed DNS. The caller holds the app lock, has
/// re-validated the selection and placed `eip_public_ip` on its instance.
pub(crate) async fn project_live(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    deployment_id: Uuid,
    eip_public_ip: &str,
    managed_dns_enabled: bool,
) -> Result<managed_dns::DnsSnapshot, ProjectLiveError> {
    let ctx = || ProjectLiveErrorCtx::new(app_id, deployment_id);

    let (status, error): (String, Option<String>) = sqlx::query_as(
        "UPDATE compute_resources cr
         SET live_deployment_id = d.id, provider_resource_id = d.instance_id, state = 'running',
             public_ip = $3, region = d.region,
             configuration = COALESCE(cr.configuration, '{}'::jsonb) || d.configuration,
             dns_status = CASE
                 WHEN NOT $4::boolean THEN cr.dns_status
                 WHEN cr.dns_status = 'ready' AND cr.public_ip = $3 THEN 'ready'
                 ELSE 'publishing'
             END,
             dns_error = CASE WHEN $4::boolean THEN NULL ELSE cr.dns_error END,
             dns_change_id = CASE
                 WHEN $4::boolean AND NOT (cr.dns_status = 'ready' AND cr.public_ip = $3) THEN NULL
                 ELSE cr.dns_change_id
             END,
             dns_release_not_before = CASE
                 WHEN $4::boolean THEN NULL ELSE cr.dns_release_not_before
             END,
             updated_at = NOW()
         FROM app_deployments d
         WHERE cr.id = $1 AND d.id = $2 AND d.app_id = cr.id
         RETURNING cr.dns_status, cr.dns_error",
    )
    .bind(app_id)
    .bind(deployment_id)
    .bind(eip_public_ip)
    .bind(managed_dns_enabled)
    .fetch_one(&mut **tx)
    .await
    .with_context(ctx())?;
    sqlx::query("UPDATE app_deployments SET activated_at = NOW() WHERE id = $1")
        .bind(deployment_id)
        .execute(&mut **tx)
        .await
        .with_context(ctx())?;
    Ok(managed_dns::DnsSnapshot { status, error })
}

/// Records Running and, iff nothing is live, attaches the app EIP and makes
/// this deployment live, refreshing the app-level projection.
pub(crate) async fn complete_running(
    state: &AppState,
    app_id: Uuid,
    deployment: &RunningDeployment,
) -> Result<Activation, CompleteRunningError> {
    let credentials = fully_managed_capacity::platform_credentials_for_region(&deployment.region);
    complete_running_with(
        &state.db,
        state.managed_dns.is_some(),
        &ec2::Ec2Client::new(&credentials),
        app_id,
        deployment,
    )
    .await
}

async fn complete_running_with(
    db: &PgPool,
    managed_dns_enabled: bool,
    address_mover: &impl AppAddressMover,
    app_id: Uuid,
    deployment: &RunningDeployment,
) -> Result<Activation, CompleteRunningError> {
    use CompleteRunningErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::lock())?;
    let (live, app_state, destroyed): (Option<Uuid>, String, bool) = sqlx::query_as(
        "SELECT live_deployment_id, state::text, destroyed_at IS NOT NULL
         FROM compute_resources WHERE id = $1 FOR UPDATE",
    )
    .bind(app_id)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    // Legacy guards its publish with `state = 'pending' AND deploy_attempt_id`;
    // a candidate must not resurrect an app suspended or destroyed meanwhile.
    if destroyed || !matches!(app_state.as_str(), "initialized" | "running") {
        return Err(CompleteRunningError::AppNotActive {
            app_id,
            state: app_state,
            location: std::panic::Location::caller(),
        });
    }

    let updated = sqlx::query(
        "UPDATE app_deployments
         SET status = 'running', running_at = NOW(), instance_id = $2, instance_type = $3,
             configuration = $4
         WHERE id = $1 AND owner_process_id = $5 AND status = 'provisioning'",
    )
    .bind(deployment.id)
    .bind(&deployment.instance_id)
    .bind(deployment.instance_type.as_deref())
    .bind(&deployment.configuration)
    .bind(*PROCESS_ID)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    if updated.rows_affected() == 0 {
        return Err(CompleteRunningError::OwnershipLost {
            deployment_id: deployment.id,
            location: std::panic::Location::caller(),
        });
    }

    // Commit Running before touching the EIP. From here on failure cleanup
    // (`fail_attempt`) never destroys this deployment, and if the API dies
    // after the EIP moves, reconciliation finishes the activation
    // (`LiveRepair::RecordLive`/`Activate`) instead of destroying it.
    tx.commit().await.with_context(Ctx::database())?;
    if !activates_on_running(live) {
        return Ok(Activation {
            role: Role::Candidate,
            live_deployment_id: live,
            dns: None,
            eip_public_ip: None,
        });
    }

    // The first commit released the app lock. Reacquire it before any EIP
    // mutation and re-read both rows: destruction or a switch may have won.
    // Hold this transaction through the EIP move and live-pointer update.
    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::lock())?;
    let (live, app_state, destroyed, status, owner, instance_id): (
        Option<Uuid>,
        String,
        bool,
        String,
        Option<Uuid>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT cr.live_deployment_id, cr.state::text, cr.destroyed_at IS NOT NULL,
                d.status, d.owner_process_id, d.instance_id
         FROM compute_resources cr JOIN app_deployments d ON d.app_id = cr.id
         WHERE cr.id = $1 AND d.id = $2
         FOR UPDATE OF cr, d",
    )
    .bind(app_id)
    .bind(deployment.id)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    if destroyed || !matches!(app_state.as_str(), "initialized" | "running") {
        return Err(CompleteRunningError::AppNotActive {
            app_id,
            state: app_state,
            location: std::panic::Location::caller(),
        });
    }
    if status != "running"
        || owner != Some(*PROCESS_ID)
        || instance_id.as_deref() != Some(deployment.instance_id.as_str())
    {
        return Err(CompleteRunningError::OwnershipLost {
            deployment_id: deployment.id,
            location: std::panic::Location::caller(),
        });
    }
    if live.is_some() && live != Some(deployment.id) {
        tx.commit().await.with_context(Ctx::database())?;
        return Ok(Activation {
            role: Role::Candidate,
            live_deployment_id: live,
            dns: None,
            eip_public_ip: None,
        });
    }

    // Accept an unassociated EIP or this instance already holding it after
    // reconciliation; never take it from another holder. On error the durable
    // Running row survives, so reconciliation can settle activation safely.
    let eip_public_ip = address_mover
        .move_address(&app_id.to_string(), &deployment.instance_id, None)
        .await
        .with_context(Ctx::attach_address())?;

    // Projects the row written above (instance, configuration) and the
    // region recorded at provisioning.
    let dns = project_live(
        &mut tx,
        app_id,
        deployment.id,
        &eip_public_ip,
        managed_dns_enabled,
    )
    .await
    .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;
    Ok(Activation {
        role: Role::Live,
        live_deployment_id: Some(deployment.id),
        dns: Some(dns),
        eip_public_ip: Some(eip_public_ip),
    })
}

/// Marks an owned, unfinished attempt failed and destroys only its own state.
/// Never touches a `running` row: an ambiguous commit in `complete_running` may
/// already have made it live. Best effort: reconciliation retries cleanup that
/// does not complete here. The meter stops only once the instance is gone.
pub(crate) async fn fail_attempt(
    state: &AppState,
    org_id: Uuid,
    app_id: Uuid,
    deployment_id: Uuid,
    message: &str,
) {
    // Scoped to the app: the deployment ID of a failed push comes from the request.
    let failed = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(
        "UPDATE app_deployments
         SET status = 'failed', failure_kind = 'provisioning', failed_at = NOW(), error = $2
         WHERE id = $1 AND owner_process_id = $3 AND status IN ('building', 'provisioning')
           AND app_id = $4 AND organization_id = $5
         RETURNING state_key, region, instance_id",
    )
    .bind(deployment_id)
    .bind(message)
    .bind(*PROCESS_ID)
    .bind(app_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await;
    let (state_key, region, instance_id) = match failed {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(error) => {
            tracing::error!(deployment_id = %deployment_id, error = %error, "failed to mark deployment failed");
            return;
        }
    };
    let cleaned = match (state_key, region) {
        (Some(_), Some(region)) => {
            deployment::destroy_deployment_state(org_id, app_id, deployment_id, &region)
                .await
                .is_ok()
        }
        _ => true, // nothing was provisioned
    };
    if cleaned {
        if let Some(instance_id) = instance_id.as_deref() {
            stop_meter(state, instance_id).await;
        }
        let _ = sqlx::query("UPDATE app_deployments SET cleaned_up_at = NOW() WHERE id = $1")
            .bind(deployment_id)
            .execute(&state.db)
            .await;
    }
}

const PROGRESS_AUTHORISED: u8 = 1;
const PROGRESS_CLAIMED: u8 = 2;

/// How far one `/deploy` request got with the deployment ID in its body. The
/// ID is caller-supplied, so error recovery touches only what the request
/// proved it may: it survives the deploy task, including a panic.
#[derive(Debug, Default)]
pub(crate) struct DeployProgress(AtomicU8);

#[derive(Debug, PartialEq, Eq)]
enum PushRecovery {
    Nothing,
    ReleaseReservation,
    FailAttempt,
}

impl DeployProgress {
    /// The caller belongs to the org, and the app to that org.
    pub(crate) fn authorise(&self) {
        self.0.fetch_max(PROGRESS_AUTHORISED, Ordering::SeqCst);
    }

    /// This request claimed the reservation (`claim_for_build`).
    pub(crate) fn claim(&self) {
        self.0.fetch_max(PROGRESS_CLAIMED, Ordering::SeqCst);
    }

    fn recovery(&self) -> PushRecovery {
        match self.0.load(Ordering::SeqCst) {
            PROGRESS_CLAIMED => PushRecovery::FailAttempt,
            PROGRESS_AUTHORISED => PushRecovery::ReleaseReservation,
            _ => PushRecovery::Nothing,
        }
    }
}

/// Settles the deployment of a failed `/deploy` request. A deployment this
/// request claimed is failed and cleaned up; an authorised request that never
/// claimed releases only a still-reserved slot of its own app (a rejection
/// before the claim must not keep the app busy); anything else is untouched.
pub(crate) async fn settle_failed_push(
    state: &AppState,
    progress: &DeployProgress,
    org_id: Uuid,
    app_id: Uuid,
    deployment_id: Uuid,
    message: &str,
) {
    match progress.recovery() {
        PushRecovery::FailAttempt => {
            fail_attempt(state, org_id, app_id, deployment_id, message).await;
        }
        PushRecovery::ReleaseReservation => {
            if let Err(error) =
                admission::release_reservation(&state.db, deployment_id, Some(app_id)).await
            {
                tracing::error!(
                    ?error,
                    "failed to release deployment reservation after deploy error"
                );
            }
        }
        PushRecovery::Nothing => {}
    }
}

pub(crate) async fn stop_meter(state: &AppState, instance_id: &str) {
    if crate::metering::stop_tracked_resource(state.internal_service_secret.as_deref(), instance_id)
        .await
        .is_err()
    {
        let _ = sqlx::query(
            "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW()
             WHERE resource_id = $1 AND status = 'running'",
        )
        .bind(instance_id)
        .execute(&state.db)
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deployment_goes_live_only_when_none_is_live() {
        assert!(activates_on_running(None));
        // The pointer survives loss of the live instance, so this holds after host failure too.
        assert!(!activates_on_running(Some(Uuid::new_v4())));
    }

    #[test]
    fn role_is_live_only_for_the_live_pointer() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(role_for(Some(a), a), Role::Live);
        assert_eq!(role_for(Some(a), b), Role::Candidate);
        // A failed first attempt is not live.
        assert_eq!(role_for(None, a), Role::Candidate);
    }

    #[test]
    fn failed_push_recovery_follows_progress() {
        let progress = DeployProgress::default();
        // Not (yet) shown to belong to the caller's org: touch nothing.
        assert_eq!(progress.recovery(), PushRecovery::Nothing);
        progress.authorise();
        // Authorised but unclaimed: never fail someone else's attempt.
        assert_eq!(progress.recovery(), PushRecovery::ReleaseReservation);
        progress.claim();
        assert_eq!(progress.recovery(), PushRecovery::FailAttempt);
        progress.authorise();
        assert_eq!(progress.recovery(), PushRecovery::FailAttempt);
    }
}

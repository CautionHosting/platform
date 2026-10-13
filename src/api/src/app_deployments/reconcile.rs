// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Reconciliation of app deployments, at startup and every minute. The API
//! runs as a single process, so work owned by another process ID was abandoned
//! by a restart. The Elastic IP association is the source of truth for the
//! live selection.

use super::destroy::{
    DestroyBackend, DestroyTarget, Platform, complete_destroy_with, destroy_and_sweep, ec2_client,
};
use super::lifecycle::{fail_attempt_with, project_live, stop_meter};
use super::{LIFECYCLE_DEPLOYMENTS, PROCESS_ID, lock_app_operations};
use crate::{AppState, deployment, ec2};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// How reconciliation settles the live pointer.
#[derive(Debug)]
pub(crate) enum LiveRepair {
    None,
    RecordLive(Uuid),
    Activate(Uuid),
    ReportUnassociated,
}

/// `live` is the live pointer, `holder` the Running deployment whose instance
/// holds the app EIP, `running` the app's Running deployments.
pub(crate) fn live_repair(
    live: Option<Uuid>,
    holder: Option<Uuid>,
    running: &[Uuid],
) -> LiveRepair {
    match (live, holder) {
        (_, Some(holder)) if live != Some(holder) => LiveRepair::RecordLive(holder),
        (_, Some(_)) => LiveRepair::None,
        (None, None) if running.len() == 1 => LiveRepair::Activate(running[0]),
        (None, None) => LiveRepair::None,
        (Some(_), None) => LiveRepair::ReportUnassociated,
    }
}

/// The AWS calls of reconciliation besides destruction. A seam so the
/// database-backed tests run without AWS; production uses [`Platform`].
pub(super) trait ReconcileBackend: DestroyBackend {
    async fn app_address(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError>;

    /// Attaches the app EIP to `instance_id`, never taking it from a holder.
    async fn attach_address(
        &self,
        app_id: Uuid,
        region: &str,
        instance_id: &str,
    ) -> Result<String, ec2::MoveAppAddressError>;

    async fn instance_runtime(
        &self,
        region: &str,
        instance_id: &str,
    ) -> Result<Option<ec2::InstanceRuntime>, ec2::DescribeInstanceRuntimeError>;
}

impl ReconcileBackend for Platform {
    async fn app_address(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
        ec2_client(region)
            .describe_app_address(&app_id.to_string())
            .await
    }

    async fn attach_address(
        &self,
        app_id: Uuid,
        region: &str,
        instance_id: &str,
    ) -> Result<String, ec2::MoveAppAddressError> {
        ec2_client(region)
            .move_app_address(&app_id.to_string(), instance_id, None)
            .await
    }

    async fn instance_runtime(
        &self,
        region: &str,
        instance_id: &str,
    ) -> Result<Option<ec2::InstanceRuntime>, ec2::DescribeInstanceRuntimeError> {
        ec2_client(region)
            .describe_instance_runtime(instance_id)
            .await
    }
}

/// One reconciliation pass. Each step logs its errors; the next one still runs.
pub(crate) async fn reconcile(state: Arc<AppState>) {
    reconcile_with(&state, &Platform).await;
}

pub(super) async fn reconcile_with(state: &AppState, backend: &impl ReconcileBackend) {
    match expire_reservations(&state.db).await {
        Ok(0) => {}
        Ok(expired) => tracing::info!(expired, "released expired deployment reservations"),
        Err(error) => {
            tracing::error!(error = %error, "failed to release expired deployment reservations");
        }
    }
    if let Err(error) = recover_abandoned_work(state, backend).await {
        tracing::error!(error = %error, "failed to list abandoned deployment work");
    }
    if let Err(error) = retry_cleanup(state, backend).await {
        tracing::error!(error = %error, "failed to list deployments awaiting cleanup");
    }
    if let Err(error) = reconcile_apps(state, backend).await {
        tracing::error!(error = %error, "failed to list deployments apps to reconcile");
    }
}

/// Failure modes for [`expire_reservations`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ExpireReservationsError {
    #[error("failed to delete expired deployment reservations [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Releases reservations no push bound (gateway restart, dropped SSH session).
pub(super) async fn expire_reservations(db: &PgPool) -> Result<u64, ExpireReservationsError> {
    sqlx::query(
        "DELETE FROM app_deployments
         WHERE status = 'reserved' AND reservation_expires_at < NOW()",
    )
    .execute(db)
    .await
    .map(|done| done.rows_affected())
    .with_context(ExpireReservationsErrorCtx::database())
}

/// Takes the app teardown lock (namespace 1, held by `destroy_resource_by_id`)
/// for the current transaction iff no teardown holds it (`$1`: the app ID).
const TEARDOWN_IDLE: &str = "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 1))";

/// Work no operation of this process still runs (`$1`: this process, `$2`:
/// [`CLEANUP_GRACE_SECS`]): unfinished work of another process ID, which a
/// restart abandoned (a failed attempt awaiting cleanup is included: a
/// cleanup that died with its process left a stale state lock), and a
/// deployment destroy of this process still `destroying` past the grace (its
/// task died or its last write failed).
const ABANDONED: &str = "(d.owner_process_id IS DISTINCT FROM $1
       AND (d.status IN ('building', 'provisioning', 'destroying')
            OR (d.status = 'failed' AND d.failure_kind = 'provisioning'
                AND d.cleaned_up_at IS NULL AND d.state_key IS NOT NULL)))
     OR (d.owner_process_id = $1 AND d.status = 'destroying'
         AND d.updated_at < NOW() - make_interval(secs => $2))";

/// Failure modes for [`recover_abandoned_work`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RecoverAbandonedWorkError {
    #[error("failed to list abandoned deployment work [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

pub(super) async fn recover_abandoned_work(
    state: &AppState,
    backend: &impl ReconcileBackend,
) -> Result<(), RecoverAbandonedWorkError> {
    let abandoned: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
        "SELECT d.app_id, d.id FROM app_deployments d WHERE {ABANDONED} ORDER BY d.created_at"
    ))
    .bind(*PROCESS_ID)
    .bind(CLEANUP_GRACE_SECS)
    .fetch_all(&state.db)
    .await
    .with_context(RecoverAbandonedWorkErrorCtx::database())?;
    for (app_id, deployment_id) in abandoned {
        if let Err(error) = recover_abandoned(state, backend, app_id, deployment_id).await {
            tracing::warn!(deployment_id = %deployment_id, error = %error, "abandoned deployment recovery will retry");
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct Adopted {
    status: String,
    #[sqlx(flatten)]
    target: DestroyTarget,
}

/// Failure modes for [`reclaim`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReclaimError {
    #[error("database error while taking over deployment {deployment_id} [{location}]")]
    Database {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to clear the state lock of deployment {deployment_id} [{location}]")]
    ClearStateLock {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Under the app lock, and only while no app teardown runs, takes
/// `deployment_id` for this process if it still matches `predicate` (one of
/// [`ABANDONED`] and [`CLEANUP_DUE`]) and deletes its state lock: no OpenTofu
/// run can still hold it. The row is re-checked here, so work settled since it
/// was listed is left alone. `None`: nothing to take now. On failure the
/// take-over rolls back, so a later pass retries.
async fn reclaim(
    state: &AppState,
    backend: &impl DestroyBackend,
    app_id: Uuid,
    deployment_id: Uuid,
    predicate: &str,
) -> Result<Option<Adopted>, ReclaimError> {
    use ReclaimErrorCtx as Ctx;

    let mut tx = state
        .db
        .begin()
        .await
        .with_context(Ctx::database(deployment_id))?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::database(deployment_id))?;
    // App teardown destroys every deployment, under this lock and whatever its
    // owner: never delete a state lock its OpenTofu holds. Retry next pass.
    let teardown_idle: bool = sqlx::query_scalar(TEARDOWN_IDLE)
        .bind(app_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .with_context(Ctx::database(deployment_id))?;
    if !teardown_idle {
        return Ok(None);
    }
    let adopted: Option<Adopted> = sqlx::query_as(&format!(
        "UPDATE app_deployments d SET owner_process_id = $1
         FROM compute_resources cr
         WHERE cr.id = d.app_id AND d.id = $3 AND ({predicate})
         RETURNING d.status, d.organization_id AS org_id, d.app_id, d.id AS deployment_id,
                   d.instance_id, d.region,
                   CASE WHEN d.cleaned_up_at IS NULL THEN d.state_key END AS state_key"
    ))
    .bind(*PROCESS_ID)
    .bind(CLEANUP_GRACE_SECS)
    .bind(deployment_id)
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::database(deployment_id))?;
    let Some(adopted) = adopted else {
        return Ok(None);
    };
    if let Some(state_key) = adopted.target.state_key.as_deref() {
        backend
            .clear_state_lock(state_key)
            .await
            .with_context(Ctx::clear_state_lock(deployment_id))?;
    }
    tx.commit()
        .await
        .with_context(Ctx::database(deployment_id))?;
    Ok(Some(adopted))
}

/// Failure modes for [`recover_abandoned`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RecoverAbandonedError {
    #[error("failed to adopt deployment {deployment_id} [{location}]")]
    Adopt {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to destroy deployment {deployment_id} [{location}]")]
    Destroy {
        deployment_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Takes ownership of one abandoned deployment, clears its stale state lock and
/// settles it: an unfinished attempt fails and its state is destroyed, an
/// interrupted destroy is re-run, and a failed cleanup is left to
/// [`retry_cleanup`]. See [`reclaim`].
pub(super) async fn recover_abandoned(
    state: &AppState,
    backend: &impl ReconcileBackend,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<(), RecoverAbandonedError> {
    use RecoverAbandonedErrorCtx as Ctx;

    let Some(Adopted { status, target }) =
        reclaim(state, backend, app_id, deployment_id, ABANDONED)
            .await
            .with_context(Ctx::adopt(deployment_id))?
    else {
        return Ok(());
    };

    match status.as_str() {
        // Never the EIP holder: `complete_running` commits Running before it
        // moves the EIP.
        "building" | "provisioning" => {
            fail_attempt_with(
                state,
                backend,
                target.org_id,
                target.app_id,
                deployment_id,
                "abandoned by an API restart",
            )
            .await;
        }
        "destroying" => complete_destroy_with(state, backend, &target)
            .await
            .with_context(Ctx::destroy(deployment_id))?,
        // A failed cleanup: `retry_cleanup` destroys it.
        _ => {}
    }
    Ok(())
}

/// Failure modes for [`retry_cleanup`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RetryCleanupError {
    #[error("failed to list deployments awaiting cleanup [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// How long an OpenTofu run of this process may still hold a deployment's
/// state lock: `fail_attempt` marks an attempt failed, and deployment
/// destruction marks it `destroying`, before their `tofu init` and `tofu
/// destroy`, each bounded by `TOFU_TIMEOUT_SECS`. Past it, `run_with_timeout`
/// has killed the run, so a lock it left is stale. The stamp is taken before
/// lock waits and EC2 calls, hence the extra 120 s.
const CLEANUP_GRACE_SECS: f64 = (2 * deployment::TOFU_TIMEOUT_SECS + 120) as f64;

/// Failed attempts of this process whose cleanup did not finish, past the
/// grace (`$1`: this process, `$2`: [`CLEANUP_GRACE_SECS`]); never the live
/// deployment (`cr`: its app). A failed deployment destroy keeps its earlier
/// `failed_at`, often none, and is due at once: its OpenTofu run had returned
/// when it was marked.
const CLEANUP_DUE: &str = "d.status = 'failed' AND d.failure_kind = 'provisioning'
     AND d.cleaned_up_at IS NULL AND d.state_key IS NOT NULL AND d.region IS NOT NULL
     AND d.owner_process_id = $1 AND d.id IS DISTINCT FROM cr.live_deployment_id
     AND (d.failed_at IS NULL OR d.failed_at < NOW() - make_interval(secs => $2))";

/// Destroys the state of failed attempts whose cleanup did not finish and
/// sweeps their leftovers, then records it and stops the meter, which
/// `fail_attempt` and a failed deployment destroy leave running while an
/// instance may exist. Only this process's rows ([`CLEANUP_DUE`]): an
/// abandoned one is adopted first. Each is reclaimed first, which deletes the
/// stale lock of an OpenTofu run killed by its timeout.
pub(super) async fn retry_cleanup(
    state: &AppState,
    backend: &impl ReconcileBackend,
) -> Result<(), RetryCleanupError> {
    // Nothing was provisioned, so no state remains (`fail_attempt` died
    // between its two updates).
    if let Err(error) = sqlx::query(
        "UPDATE app_deployments SET cleaned_up_at = NOW()
         WHERE status = 'failed' AND cleaned_up_at IS NULL
           AND state_key IS NULL AND instance_id IS NULL",
    )
    .execute(&state.db)
    .await
    {
        tracing::error!(error = %error, "failed to record failed attempts that provisioned nothing");
    }

    let pending: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
        "SELECT d.app_id, d.id
         FROM app_deployments d JOIN compute_resources cr ON cr.id = d.app_id
         WHERE {CLEANUP_DUE}
         ORDER BY d.failed_at"
    ))
    .bind(*PROCESS_ID)
    .bind(CLEANUP_GRACE_SECS)
    .fetch_all(&state.db)
    .await
    .with_context(RetryCleanupErrorCtx::database())?;
    for (app_id, deployment_id) in pending {
        // `None` also while an app teardown runs: it destroys this state itself.
        let target = match reclaim(state, backend, app_id, deployment_id, CLEANUP_DUE).await {
            Ok(Some(Adopted { target, .. })) => target,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(deployment_id = %deployment_id, error = %error, "deployment cleanup will retry");
                continue;
            }
        };
        let Some(region) = target.region.as_deref() else {
            continue;
        };
        if let Err(error) = destroy_and_sweep(
            &state.db,
            backend,
            target.org_id,
            target.app_id,
            deployment_id,
            region,
        )
        .await
        {
            tracing::warn!(deployment_id = %deployment_id, error = %error, "deployment cleanup will retry");
            continue;
        }
        if let Err(error) = sqlx::query(
            "UPDATE app_deployments SET cleaned_up_at = NOW()
             WHERE id = $1 AND cleaned_up_at IS NULL",
        )
        .bind(deployment_id)
        .execute(&state.db)
        .await
        {
            tracing::error!(deployment_id = %deployment_id, error = %error, "failed to record deployment cleanup");
            continue;
        }
        if let Some(instance_id) = target.instance_id.as_deref() {
            stop_meter(state, instance_id).await;
        }
    }
    Ok(())
}

/// The apps whose live selection is reconciled (`$1`: the deployments
/// lifecycle), re-checked under the app lock before any write.
const RECONCILED_APP: &str = "cr.lifecycle = $1 AND cr.app_network IS NOT NULL
     AND cr.region IS NOT NULL AND cr.destroyed_at IS NULL
     AND cr.state NOT IN ('terminating', 'stopped')";

/// A reconciled app as read before repair.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct DeploymentsApp {
    pub(super) id: Uuid,
    pub(super) region: String,
    pub(super) live_deployment_id: Option<Uuid>,
}

/// Failure modes for [`reconcile_apps`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReconcileAppsError {
    #[error("failed to list deployments apps [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Repairs each app's live pointer from the EIP association, then marks its
/// Running deployments whose instance is confirmed gone.
pub(super) async fn reconcile_apps(
    state: &AppState,
    backend: &impl ReconcileBackend,
) -> Result<(), ReconcileAppsError> {
    let apps: Vec<DeploymentsApp> = sqlx::query_as(&format!(
        "SELECT cr.id, cr.region, cr.live_deployment_id FROM compute_resources cr
         WHERE {RECONCILED_APP}"
    ))
    .bind(LIFECYCLE_DEPLOYMENTS)
    .fetch_all(&state.db)
    .await
    .with_context(ReconcileAppsErrorCtx::database())?;
    for app in apps {
        let running: Vec<(Uuid, String)> = match sqlx::query_as(
            "SELECT id, instance_id FROM app_deployments
             WHERE app_id = $1 AND status = 'running' AND instance_id IS NOT NULL
             ORDER BY running_at",
        )
        .bind(app.id)
        .fetch_all(&state.db)
        .await
        {
            Ok(running) => running,
            Err(error) => {
                tracing::error!(app_id = %app.id, error = %error, "failed to list running deployments");
                continue;
            }
        };
        if let Err(error) = repair_live(state, backend, &app, &running).await {
            tracing::warn!(app_id = %app.id, error = %error, "live deployment repair will retry");
        }
        for (deployment_id, instance_id) in &running {
            mark_runtime_lost(state, backend, &app.region, *deployment_id, instance_id).await;
        }
    }
    Ok(())
}

/// Failure modes for [`repair_live`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RepairLiveError {
    #[error("failed to read the Elastic IP of app {app_id} [{location}]")]
    DescribeAddress {
        app_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to attach the Elastic IP of app {app_id} [{location}]")]
    AttachAddress {
        app_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("database error while repairing the live deployment of app {app_id} [{location}]")]
    Database {
        app_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Settles the live pointer from the EIP association (`running`:
/// `(deployment, instance)` of the app's Running deployments). A write takes
/// the app lock and re-reads the app; if the pointer differs from `app`
/// (a switch or activation committed meanwhile), the app is left to the next
/// pass instead of being reverted.
pub(super) async fn repair_live(
    state: &AppState,
    backend: &impl ReconcileBackend,
    app: &DeploymentsApp,
    running: &[(Uuid, String)],
) -> Result<(), RepairLiveError> {
    use RepairLiveErrorCtx as Ctx;

    let address = backend
        .app_address(app.id, &app.region)
        .await
        .with_context(Ctx::describe_address(app.id))?;
    let holder = match address.instance_id.as_deref() {
        None => None,
        Some(instance_id) => {
            let holder: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM app_deployments
                 WHERE app_id = $1 AND instance_id = $2 AND status = 'running'",
            )
            .bind(app.id)
            .bind(instance_id)
            .fetch_optional(&state.db)
            .await
            .with_context(Ctx::database(app.id))?;
            if holder.is_none() {
                // Reported for operator repair; switches refuse it meanwhile
                // (`AssociationMismatch`).
                tracing::error!(app_id = %app.id, instance_id, "app Elastic IP is held by an instance of no Running deployment");
                return Ok(());
            }
            holder
        }
    };
    let running_ids: Vec<Uuid> = running.iter().map(|(id, _)| *id).collect();
    let (deployment_id, activate) = match live_repair(app.live_deployment_id, holder, &running_ids)
    {
        LiveRepair::None => return Ok(()),
        LiveRepair::ReportUnassociated => {
            tracing::warn!(app_id = %app.id, live_deployment_id = ?app.live_deployment_id, "app Elastic IP is unassociated; the live deployment is unreachable until a switch");
            return Ok(());
        }
        LiveRepair::RecordLive(id) => (id, false),
        LiveRepair::Activate(id) => (id, true),
    };

    let mut tx = state.db.begin().await.with_context(Ctx::database(app.id))?;
    lock_app_operations(&mut tx, app.id)
        .await
        .with_context(Ctx::database(app.id))?;
    let current: Option<(Option<Uuid>, String)> = sqlx::query_as(&format!(
        "SELECT cr.live_deployment_id, d.instance_id
         FROM compute_resources cr JOIN app_deployments d ON d.app_id = cr.id
         WHERE cr.id = $2 AND d.id = $3 AND d.status = 'running' AND d.instance_id IS NOT NULL
           AND {RECONCILED_APP}
         FOR UPDATE OF cr, d"
    ))
    .bind(LIFECYCLE_DEPLOYMENTS)
    .bind(app.id)
    .bind(deployment_id)
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::database(app.id))?;
    let Some((live, instance_id)) = current else {
        return Ok(());
    };
    if live != app.live_deployment_id {
        tracing::info!(app_id = %app.id, "live deployment changed during reconciliation; retrying next pass");
        return Ok(());
    }
    let eip_public_ip = if activate {
        backend
            .attach_address(app.id, &app.region, &instance_id)
            .await
            .with_context(Ctx::attach_address(app.id))?
    } else {
        address.public_ip
    };
    project_live(
        &mut tx,
        app.id,
        deployment_id,
        &eip_public_ip,
        state.managed_dns.is_some(),
    )
    .await
    .with_context(Ctx::database(app.id))?;
    tx.commit().await.with_context(Ctx::database(app.id))?;
    tracing::info!(app_id = %app.id, deployment_id = %deployment_id, activated = activate, "recorded the live deployment from the Elastic IP association");
    Ok(())
}

/// Only a positive confirmation counts; a stopped instance is not lost.
fn runtime_gone(runtime: Option<&ec2::InstanceRuntime>) -> bool {
    runtime.is_none_or(|runtime| matches!(runtime.state.as_str(), "terminated" | "shutting-down"))
}

/// Marks a Running deployment `runtime_lost` once EC2 confirms its instance
/// gone, and stops its meter. The live pointer stays (a recovery switch moves
/// it) and so does the state (`destroy -d` destroys it).
async fn mark_runtime_lost(
    state: &AppState,
    backend: &impl ReconcileBackend,
    region: &str,
    deployment_id: Uuid,
    instance_id: &str,
) {
    match backend.instance_runtime(region, instance_id).await {
        Ok(runtime) if runtime_gone(runtime.as_ref()) => {}
        Ok(_) => return,
        Err(error) => {
            tracing::warn!(deployment_id = %deployment_id, error = %error, "failed to read deployment runtime");
            return;
        }
    }
    let marked = sqlx::query(
        "UPDATE app_deployments
         SET status = 'failed', failure_kind = 'runtime_lost', failed_at = NOW(),
             error = 'instance terminated'
         WHERE id = $1 AND status = 'running' AND instance_id = $2",
    )
    .bind(deployment_id)
    .bind(instance_id)
    .execute(&state.db)
    .await;
    match marked {
        Ok(done) if done.rows_affected() == 1 => {
            tracing::warn!(deployment_id = %deployment_id, instance_id, "deployment runtime lost");
            stop_meter(state, instance_id).await;
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(deployment_id = %deployment_id, error = %error, "failed to mark deployment runtime lost");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_pointer_follows_the_eip_holder() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(matches!(
            live_repair(Some(a), Some(a), &[a, b]),
            LiveRepair::None
        ));
        // Switch interrupted after the EIP moved: record the holder.
        assert!(
            matches!(live_repair(Some(a), Some(b), &[a, b]), LiveRepair::RecordLive(id) if id == b)
        );
        // Activation interrupted after the EIP moved.
        assert!(matches!(live_repair(None, Some(a), &[a]), LiveRepair::RecordLive(id) if id == a));
        // Activation interrupted before the EIP moved: finish activating the only Running deployment.
        assert!(matches!(live_repair(None, None, &[a]), LiveRepair::Activate(id) if id == a));
        // Never guess between several deployments.
        assert!(matches!(live_repair(None, None, &[a, b]), LiveRepair::None));
        // A live pointer with an unassociated EIP is reported, not changed.
        assert!(matches!(
            live_repair(Some(a), None, &[a]),
            LiveRepair::ReportUnassociated
        ));
    }

    #[test]
    fn only_a_confirmed_absence_is_a_lost_runtime() {
        let runtime = |state: &str| ec2::InstanceRuntime {
            state: state.to_string(),
            public_ip: None,
        };
        assert!(runtime_gone(None));
        for gone in ["terminated", "shutting-down"] {
            assert!(runtime_gone(Some(&runtime(gone))), "{gone}");
        }
        for present in ["pending", "running", "stopping", "stopped"] {
            assert!(!runtime_gone(Some(&runtime(present))), "{present}");
        }
    }
}

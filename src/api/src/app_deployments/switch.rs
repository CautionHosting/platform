// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Passkey-signed switch: moves the app Elastic IP to a Running deployment
//! and records it live. The gateway refuses session-only and SSH-signed calls.

use super::handlers::TLS_AFTER_SWITCH_SQL;
use super::lifecycle::{AppAddressMover, project_live};
use super::{LIFECYCLE_DEPLOYMENTS, lock_app_operations};
use crate::{AppState, AuthContext, ec2, fully_managed_capacity};
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

#[derive(serde::Deserialize)]
pub(crate) struct SwitchRequest {
    pub(crate) expected_live_deployment_id: Option<Uuid>,
    #[serde(default)]
    pub(crate) acknowledged_verification: bool,
    /// Required when the target obtains its certificate only after switching.
    #[serde(default)]
    pub(crate) acknowledged_tls_pending: bool,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct SwitchResponse {
    pub(crate) live_deployment_id: Uuid,
    pub(crate) previous_live_deployment_id: Option<Uuid>,
    /// The app Elastic IP.
    pub(crate) stable_ip: String,
    /// This switch moved the address to a deployment that obtains its
    /// certificate only now.
    pub(crate) tls_after_switch: bool,
}

pub(crate) struct SwitchView {
    pub(crate) app_state: String,
    pub(crate) live_deployment_id: Option<Uuid>,
    pub(crate) target_id: Uuid,
    pub(crate) target_status: String,
    pub(crate) target_instance_id: Option<String>,
    pub(crate) expected_live_deployment_id: Option<Uuid>,
    pub(crate) acknowledged_verification: bool,
    pub(crate) target_tls_after_switch: bool,
    pub(crate) acknowledged_tls_pending: bool,
}

#[derive(Debug)]
pub(crate) enum SwitchPlan {
    AlreadyLive,
    Move,
}

#[derive(Debug)]
pub(crate) enum SwitchRejection {
    NotAcknowledged,
    AppUnavailable,
    NotRunning,
    TlsNotAcknowledged,
    Stale,
}

pub(crate) fn switch_precondition(view: &SwitchView) -> Result<SwitchPlan, SwitchRejection> {
    if !view.acknowledged_verification {
        return Err(SwitchRejection::NotAcknowledged);
    }
    if !matches!(
        view.app_state.as_str(),
        "running" | "initialized" | "failed"
    ) {
        return Err(SwitchRejection::AppUnavailable);
    }
    if view.expected_live_deployment_id != view.live_deployment_id {
        return Err(SwitchRejection::Stale);
    }
    if view.live_deployment_id == Some(view.target_id) {
        return Ok(SwitchPlan::AlreadyLive);
    }
    if view.target_status != "running" || view.target_instance_id.is_none() {
        return Err(SwitchRejection::NotRunning);
    }
    if view.target_tls_after_switch && !view.acknowledged_tls_pending {
        return Err(SwitchRejection::TlsNotAcknowledged);
    }
    Ok(SwitchPlan::Move)
}

/// The instance the app EIP must be taken from: the live deployment's, except
/// after reconciliation confirmed that runtime gone (`runtime_lost`). Its
/// terminated instance left the address unassigned, and the recovery switch
/// binds that observed association (spec: standalone host failure, stage 1).
pub(crate) fn expected_holder(
    live_instance_id: Option<String>,
    live_status: Option<&str>,
    live_failure_kind: Option<&str>,
) -> Option<String> {
    if live_status == Some("failed") && live_failure_kind == Some("runtime_lost") {
        return None;
    }
    live_instance_id
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SwitchError {
    #[error("deployment not found [{location}]")]
    NotFound { location: Location },
    #[error("switch rejected: {rejection:?} [{location}]")]
    Rejected {
        rejection: SwitchRejection,
        location: Location,
    },
    #[error("target failed the platform health check [{location}]")]
    Unhealthy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Elastic IP is unassigned or held by an unexpected instance [{location}]")]
    AssociationMismatch { location: Location },
    #[error("AWS error while switching [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("database error while switching [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SwitchError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "Deployment not found."),
            Self::Rejected {
                rejection: SwitchRejection::NotAcknowledged,
                ..
            } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Acknowledge that the deployment was verified and tested.",
            ),
            Self::Rejected {
                rejection: SwitchRejection::AppUnavailable,
                ..
            } => (
                StatusCode::CONFLICT,
                "The app cannot switch while it is suspended or being destroyed.",
            ),
            Self::Rejected {
                rejection: SwitchRejection::NotRunning,
                ..
            } => (
                StatusCode::CONFLICT,
                "Only a Running deployment can become live.",
            ),
            Self::Rejected {
                rejection: SwitchRejection::TlsNotAcknowledged,
                ..
            } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "This deployment obtains its TLS certificate only after switching; acknowledge that TLS verification is pending.",
            ),
            Self::Rejected {
                rejection: SwitchRejection::Stale,
                ..
            } => (
                StatusCode::CONFLICT,
                "The live deployment changed; review and confirm again.",
            ),
            Self::Unhealthy { .. } => (
                StatusCode::CONFLICT,
                "The deployment failed the platform health check.",
            ),
            Self::AssociationMismatch { .. } => (
                StatusCode::CONFLICT,
                "The app address is unassigned or held by an unexpected instance; switching is blocked until it is repaired.",
            ),
            Self::Aws { .. } | Self::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Switch failed.")
            }
        };
        tracing::warn!(error = %self, "deployment switch failed");
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[derive(sqlx::FromRow)]
struct SwitchRow {
    app_state: String,
    live_deployment_id: Option<Uuid>,
    region: Option<String>,
    target_status: String,
    target_instance_id: Option<String>,
    target_tls_after_switch: bool,
    live_instance_id: Option<String>,
    live_status: Option<String>,
    live_failure_kind: Option<String>,
}

/// The target's switch facts; `suffix` appends a locking clause. Binds `$1`
/// app, `$2` target deployment, `$3` caller (an org member) and `$4` the
/// deployments lifecycle.
fn switch_row_sql(suffix: &str) -> String {
    format!(
        "SELECT cr.state::text AS app_state, cr.live_deployment_id, cr.region,
        d.status AS target_status, d.instance_id AS target_instance_id,
        {TLS_AFTER_SWITCH_SQL} AS target_tls_after_switch,
        l.instance_id AS live_instance_id, l.status AS live_status,
        l.failure_kind AS live_failure_kind
     FROM compute_resources cr
     JOIN organization_members om ON om.organization_id = cr.organization_id AND om.user_id = $3
     JOIN app_deployments d ON d.app_id = cr.id AND d.id = $2
     LEFT JOIN app_deployments l ON l.id = cr.live_deployment_id
     WHERE cr.id = $1 AND cr.lifecycle = $4 AND cr.destroyed_at IS NULL{suffix}"
    )
}

/// The plan, app region and target instance, or why the switch is refused.
fn check(
    row: &SwitchRow,
    deployment_id: Uuid,
    request: &SwitchRequest,
) -> Result<(SwitchPlan, String, String), SwitchError> {
    let plan = switch_precondition(&SwitchView {
        app_state: row.app_state.clone(),
        live_deployment_id: row.live_deployment_id,
        target_id: deployment_id,
        target_status: row.target_status.clone(),
        target_instance_id: row.target_instance_id.clone(),
        expected_live_deployment_id: request.expected_live_deployment_id,
        acknowledged_verification: request.acknowledged_verification,
        target_tls_after_switch: row.target_tls_after_switch,
        acknowledged_tls_pending: request.acknowledged_tls_pending,
    })
    .map_err(|rejection| SwitchError::Rejected {
        rejection,
        location: std::panic::Location::caller(),
    })?;
    let (Some(region), Some(instance_id)) = (row.region.clone(), row.target_instance_id.clone())
    else {
        return Err(SwitchError::NotFound {
            location: std::panic::Location::caller(),
        });
    };
    Ok((plan, region, instance_id))
}

pub(crate) async fn switch_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((app_id, deployment_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SwitchRequest>,
) -> Result<Json<SwitchResponse>, SwitchError> {
    use SwitchErrorCtx as Ctx;

    // 1. Validate and health-check without locks: the health wait can take
    //    ~70 s and must not block pushes, destroys or other switches.
    let row: Option<SwitchRow> = sqlx::query_as(&switch_row_sql(""))
        .bind(app_id)
        .bind(deployment_id)
        .bind(auth.user_id)
        .bind(LIFECYCLE_DEPLOYMENTS)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?;
    let Some(row) = row else {
        return Err(SwitchError::NotFound {
            location: std::panic::Location::caller(),
        });
    };
    let (plan, region, instance_id) = check(&row, deployment_id, &request)?;
    let ec2 = ec2::Ec2Client::new(&fully_managed_capacity::platform_credentials_for_region(
        &region,
    ));
    if let SwitchPlan::Move = plan {
        let runtime = ec2
            .describe_instance_runtime(&instance_id)
            .await
            .with_context(Ctx::aws())?;
        let Some(public_ip) = runtime
            .filter(|runtime| runtime.state == "running")
            .and_then(|runtime| runtime.public_ip)
        else {
            return Err(SwitchError::Rejected {
                rejection: SwitchRejection::NotRunning,
                location: std::panic::Location::caller(),
            });
        };
        crate::wait_for_deployment_health(&public_ip, 15)
            .await
            .with_context(Ctx::unhealthy())?;
    }

    // 2. The AWS calls under the lock take seconds, not the health wait.
    let response = commit_switch(
        &state.db,
        state.managed_dns.is_some(),
        &ec2,
        auth.user_id,
        app_id,
        deployment_id,
        &request,
    )
    .await?;
    // A `publishing` DNS state is published by the managed DNS reconciler.
    Ok(Json(response))
}

/// Re-reads after a move while EC2 still shows another holder.
const ASSOCIATION_READ_RETRIES: u32 = 3;
const ASSOCIATION_READ_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Reads the address, re-reading up to `retries` more times (`interval`
/// apart) while `target` does not hold it. Returns the last read.
async fn observe_holder(
    address: &impl AppAddressMover,
    resource_id: &str,
    target: &str,
    retries: u32,
    interval: std::time::Duration,
) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
    let mut observed = address.describe_address(resource_id).await?;
    for _ in 0..retries {
        if observed.instance_id.as_deref() == Some(target) {
            break;
        }
        tokio::time::sleep(interval).await;
        observed = address.describe_address(resource_id).await?;
    }
    Ok(observed)
}

/// Re-validates under the app lock (the expectation check catches a
/// concurrent switch), moves the address from the expected holder only,
/// confirms the association and records the target live. If the process dies
/// between the move and the commit, reconciliation records the EIP holder live.
pub(super) async fn commit_switch(
    db: &PgPool,
    managed_dns_enabled: bool,
    address: &impl AppAddressMover,
    user_id: Uuid,
    app_id: Uuid,
    deployment_id: Uuid,
    request: &SwitchRequest,
) -> Result<SwitchResponse, SwitchError> {
    use SwitchErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::database())?;
    let row: Option<SwitchRow> = sqlx::query_as(&switch_row_sql(" FOR UPDATE OF cr, d"))
        .bind(app_id)
        .bind(deployment_id)
        .bind(user_id)
        .bind(LIFECYCLE_DEPLOYMENTS)
        .fetch_optional(&mut *tx)
        .await
        .with_context(Ctx::database())?;
    let Some(row) = row else {
        return Err(SwitchError::NotFound {
            location: std::panic::Location::caller(),
        });
    };
    let (plan, _, instance_id) = check(&row, deployment_id, request)?;
    let resource_id = app_id.to_string();
    if let SwitchPlan::Move = plan {
        // Spec: an unassociated EIP, or one held by anything but the expected
        // holder, blocks the switch for operator repair.
        let holder = expected_holder(
            row.live_instance_id.clone(),
            row.live_status.as_deref(),
            row.live_failure_kind.as_deref(),
        );
        match address
            .move_address(&resource_id, &instance_id, holder.as_deref())
            .await
        {
            Ok(_) => {}
            Err(ec2::MoveAppAddressError::HolderMismatch { .. }) => {
                return Err(SwitchError::AssociationMismatch {
                    location: std::panic::Location::caller(),
                });
            }
            Err(error) => return Err(error).with_context(Ctx::aws()),
        }
    }
    // Confirm the observed association: it is the source of truth for the
    // live selection. Selecting the live deployment is a no-op once confirmed.
    // EC2 reads can lag a just-made association: after a move, re-read a few
    // times before treating a stale holder as a mismatch.
    let retries = if matches!(plan, SwitchPlan::Move) {
        ASSOCIATION_READ_RETRIES
    } else {
        0
    };
    let observed = observe_holder(
        address,
        &resource_id,
        &instance_id,
        retries,
        ASSOCIATION_READ_INTERVAL,
    )
    .await
    .with_context(Ctx::aws())?;
    if observed.instance_id.as_deref() != Some(instance_id.as_str()) {
        return Err(SwitchError::AssociationMismatch {
            location: std::panic::Location::caller(),
        });
    }
    if let SwitchPlan::Move = plan {
        project_live(
            &mut tx,
            app_id,
            deployment_id,
            &observed.public_ip,
            managed_dns_enabled,
        )
        .await
        .with_context(Ctx::database())?;
    }
    tx.commit().await.with_context(Ctx::database())?;
    Ok(SwitchResponse {
        live_deployment_id: deployment_id,
        previous_live_deployment_id: row.live_deployment_id.filter(|id| *id != deployment_id),
        stable_ip: observed.public_ip,
        tls_after_switch: matches!(plan, SwitchPlan::Move) && row.target_tls_after_switch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(live: Option<Uuid>, target: Uuid, status: &str, expected: Option<Uuid>) -> SwitchView {
        SwitchView {
            app_state: "running".to_string(),
            live_deployment_id: live,
            target_id: target,
            target_status: status.to_string(),
            target_instance_id: Some("i-0abc".to_string()),
            expected_live_deployment_id: expected,
            acknowledged_verification: true,
            target_tls_after_switch: false,
            acknowledged_tls_pending: false,
        }
    }

    #[test]
    fn enclave_tls_target_requires_a_pending_tls_acknowledgement() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut pending = view(Some(a), b, "running", Some(a));
        pending.target_tls_after_switch = true;
        assert!(matches!(
            switch_precondition(&pending),
            Err(SwitchRejection::TlsNotAcknowledged)
        ));
        pending.acknowledged_tls_pending = true;
        assert!(matches!(
            switch_precondition(&pending),
            Ok(SwitchPlan::Move)
        ));
        // Re-selecting the live deployment moves nothing and needs no acknowledgement.
        let mut live = view(Some(b), b, "running", Some(b));
        live.target_tls_after_switch = true;
        assert!(matches!(
            switch_precondition(&live),
            Ok(SwitchPlan::AlreadyLive)
        ));
    }

    #[test]
    fn switch_requires_a_running_non_live_target_and_fresh_expectation() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(matches!(
            switch_precondition(&view(Some(a), b, "running", Some(a))),
            Ok(SwitchPlan::Move)
        ));
        assert!(matches!(
            switch_precondition(&view(Some(b), b, "running", Some(b))),
            Ok(SwitchPlan::AlreadyLive)
        ));
        assert!(matches!(
            switch_precondition(&view(Some(a), b, "building", Some(a))),
            Err(SwitchRejection::NotRunning)
        ));
        assert!(matches!(
            switch_precondition(&view(Some(a), b, "running", None)),
            Err(SwitchRejection::Stale)
        ));
    }

    #[test]
    fn switch_requires_acknowledgement_and_an_available_app() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut unacknowledged = view(Some(a), b, "running", Some(a));
        unacknowledged.acknowledged_verification = false;
        assert!(matches!(
            switch_precondition(&unacknowledged),
            Err(SwitchRejection::NotAcknowledged)
        ));
        let mut suspended = view(Some(a), b, "running", Some(a));
        suspended.app_state = "stopped".to_string();
        assert!(matches!(
            switch_precondition(&suspended),
            Err(SwitchRejection::AppUnavailable)
        ));
    }

    #[test]
    fn a_lost_live_runtime_expects_an_unassigned_address() {
        let live = Some("i-live".to_string());
        assert_eq!(
            expected_holder(live.clone(), Some("running"), None),
            Some("i-live".to_string())
        );
        // Confirmed gone (reconciliation): its terminated instance released the EIP.
        assert_eq!(
            expected_holder(live.clone(), Some("failed"), Some("runtime_lost")),
            None
        );
        assert_eq!(
            expected_holder(live, Some("failed"), Some("provisioning")),
            Some("i-live".to_string())
        );
        assert_eq!(expected_holder(None, None, None), None);
    }

    /// Serves each scripted holder in turn, then repeats the last.
    struct ScriptedReads {
        holders: Vec<Option<&'static str>>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedReads {
        fn new(holders: Vec<Option<&'static str>>) -> Self {
            Self {
                holders,
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl AppAddressMover for ScriptedReads {
        async fn move_address(
            &self,
            _resource_id: &str,
            _target: &str,
            _expected_holder: Option<&str>,
        ) -> Result<String, ec2::MoveAppAddressError> {
            unreachable!("the confirmation only reads")
        }

        async fn describe_address(
            &self,
            _resource_id: &str,
        ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
            let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let holder = self.holders[read.min(self.holders.len() - 1)];
            Ok(ec2::AppAddress {
                allocation_id: "eipalloc-test".to_string(),
                public_ip: "198.51.100.7".to_string(),
                instance_id: holder.map(str::to_string),
            })
        }
    }

    #[tokio::test]
    async fn a_stale_read_after_the_move_is_retried_until_the_target_holds_the_address() {
        let delay = std::time::Duration::ZERO;
        let stale_then_fresh =
            ScriptedReads::new(vec![Some("i-old"), Some("i-old"), Some("i-new")]);
        let observed = observe_holder(&stale_then_fresh, "app", "i-new", 3, delay)
            .await
            .unwrap();
        assert_eq!(observed.instance_id.as_deref(), Some("i-new"));
        assert_eq!(stale_then_fresh.reads(), 3);

        // Still stale after every retry: the last read is returned (a mismatch).
        let stuck = ScriptedReads::new(vec![Some("i-old")]);
        let observed = observe_holder(&stuck, "app", "i-new", 3, delay)
            .await
            .unwrap();
        assert_eq!(observed.instance_id.as_deref(), Some("i-old"));
        assert_eq!(stuck.reads(), 4);

        // No retries (no move was made): one read.
        let single = ScriptedReads::new(vec![Some("i-old")]);
        observe_holder(&single, "app", "i-new", 0, delay)
            .await
            .unwrap();
        assert_eq!(single.reads(), 1);
    }
}

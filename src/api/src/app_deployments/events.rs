// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Switch and destroy history (`deployment_events`). An operation's
//! `requested` row is written before it executes; its outcome is appended.
//! What a crash leaves unanswered, reconciliation settles from AWS-derived state.

use super::PROCESS_ID;
use crate::AuthContext;
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Switch,
    DeploymentDestroy,
    AppDestroy,
}

impl Operation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Switch => "switch",
            Self::DeploymentDestroy => "deployment_destroy",
            Self::AppDestroy => "app_destroy",
        }
    }
}

/// Appended after an operation's `requested` row (which `begin` writes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Succeeded,
    Rejected,
    Failed,
    /// Completed, as observed by reconciliation after the request ended.
    Observed,
}

impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Observed => "observed",
        }
    }
}

pub(crate) struct NewOperation<'a> {
    pub(crate) org_id: Uuid,
    pub(crate) app_id: Uuid,
    pub(crate) operation: Operation,
    pub(crate) actor: &'a AuthContext,
    pub(crate) previous_deployment_id: Option<Uuid>,
    pub(crate) target_deployment_id: Option<Uuid>,
    pub(crate) signed_request_id: Option<Uuid>,
}

/// Error summaries shown to the tenant: the API's client message, bounded.
pub(crate) fn safe_error(message: &str) -> String {
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect()
}

/// Failure modes for [`begin`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to record the {operation} request for app {app_id} [{location}]")]
pub(crate) struct BeginOperationError {
    app_id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// Fails the operation when the request cannot be recorded: history must
/// never miss an executed switch or destruction.
pub(crate) async fn begin<'c>(
    db: impl sqlx::PgExecutor<'c>,
    new: NewOperation<'_>,
) -> Result<Uuid, BeginOperationError> {
    let (app_id, operation) = (new.app_id, new.operation);
    let operation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployment_events
             (operation_id, organization_id, app_id, operation, outcome, actor_user_id,
              auth_method, previous_deployment_id, target_deployment_id, signed_request_id,
              owner_process_id)
         VALUES ($1, $2, $3, $4, 'requested', $5, $6, $7, $8, $9, $10)",
    )
    .bind(operation_id)
    .bind(new.org_id)
    .bind(new.app_id)
    .bind(operation.as_str())
    .bind(new.actor.user_id)
    .bind(new.actor.auth_method)
    .bind(new.previous_deployment_id)
    .bind(new.target_deployment_id)
    .bind(new.signed_request_id)
    .bind(*PROCESS_ID)
    .execute(db)
    .await
    .with_context(BeginOperationErrorCtx::new(app_id, operation.as_str()))?;
    Ok(operation_id)
}

pub(crate) async fn finish(db: &PgPool, operation_id: Uuid, outcome: Outcome, error: Option<&str>) {
    let result = sqlx::query(
        "INSERT INTO deployment_events (operation_id, organization_id, app_id, operation, outcome, error)
         SELECT r.operation_id, r.organization_id, r.app_id, r.operation, $2, $3
         FROM deployment_events r WHERE r.operation_id = $1 AND r.outcome = 'requested'
           AND NOT EXISTS (SELECT 1 FROM deployment_events o
                           WHERE o.operation_id = r.operation_id AND o.outcome <> 'requested')
         ON CONFLICT (operation_id) WHERE outcome <> 'requested' DO NOTHING",
    )
    .bind(operation_id)
    .bind(outcome.as_str())
    .bind(error.map(safe_error))
    .execute(db)
    .await;
    if let Err(error) = result {
        tracing::error!(%operation_id, error = %error, "failed to record a deployment operation outcome");
    }
}

/// The switch failed after it may have moved the address: reconciliation
/// settles it from the observed association instead of this process.
pub(crate) async fn release(db: &PgPool, operation_id: Uuid) {
    let result = sqlx::query(
        "UPDATE deployment_events SET owner_process_id = NULL
         WHERE operation_id = $1 AND outcome = 'requested'",
    )
    .bind(operation_id)
    .execute(db)
    .await;
    if let Err(error) = result {
        tracing::error!(%operation_id, error = %error, "failed to hand a deployment operation to reconciliation");
    }
}

/// What reconciliation sees after an interrupted operation.
pub(crate) enum Observation<'a> {
    /// Switch: the deployment whose instance holds the app EIP, as live repair confirmed it.
    Holder(Option<Uuid>),
    /// Switch: the app was destroyed meanwhile.
    AppGone,
    /// Deployment destroy.
    Deployment {
        status: Option<&'a str>,
        cleaned_up: bool,
    },
    /// App destroy.
    App { destroyed: bool, state: &'a str },
}

/// The outcome of an operation abandoned by an API restart; `None` while the
/// reconciler or teardown loop is still completing it.
pub(crate) fn settled_outcome(
    target: Option<Uuid>,
    observation: Observation<'_>,
) -> Option<(Outcome, Option<&'static str>)> {
    match observation {
        Observation::Holder(holder) if holder.is_some() && holder == target => {
            Some((Outcome::Observed, None))
        }
        Observation::Holder(_) => Some((
            Outcome::Failed,
            Some("Interrupted before the address moved; the previous selection stands."),
        )),
        Observation::AppGone => Some((Outcome::Failed, Some("The app was destroyed."))),
        Observation::Deployment {
            status: Some("destroyed"),
            ..
        } => Some((Outcome::Observed, None)),
        // Still destroying, or its cleanup is being retried.
        Observation::Deployment {
            status: Some("destroying"),
            ..
        }
        | Observation::Deployment {
            status: Some("failed"),
            cleaned_up: false,
        } => None,
        Observation::Deployment { .. } => Some((
            Outcome::Failed,
            Some("Interrupted by an API restart; destroy the deployment again."),
        )),
        Observation::App {
            destroyed: true, ..
        } => Some((Outcome::Observed, None)),
        Observation::App {
            state: "terminating",
            ..
        } => None,
        Observation::App { .. } => Some((
            Outcome::Failed,
            Some("Interrupted by an API restart; destroy the app again."),
        )),
    }
}

/// Failure modes for [`settle_interrupted`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SettleError {
    #[error("database error while listing interrupted deployment operations [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Open requests no running request will answer: the owner process is gone,
/// or the request was released.
const OPEN_ELSEWHERE: &str = "r.outcome = 'requested' AND r.owner_process_id IS DISTINCT FROM $1
    AND NOT EXISTS (SELECT 1 FROM deployment_events o
                    WHERE o.operation_id = r.operation_id AND o.outcome <> 'requested')";

/// Called by live repair once it has confirmed the app's EIP holder, so a
/// switch is settled from the association, never from a lagging pointer.
pub(crate) async fn settle_switches(db: &PgPool, app_id: Uuid, holder: Option<Uuid>) {
    // Only static SQL fragments are interpolated; runtime values are bound below.
    let open: Result<Vec<(Uuid, Option<Uuid>)>, _> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT r.operation_id, r.target_deployment_id FROM deployment_events r
         WHERE r.app_id = $2 AND r.operation = 'switch' AND {OPEN_ELSEWHERE}"
    )))
    .bind(*PROCESS_ID)
    .bind(app_id)
    .fetch_all(db)
    .await;
    match open {
        Ok(open) => {
            for (operation_id, target) in open {
                if let Some((outcome, error)) = settled_outcome(target, Observation::Holder(holder))
                {
                    finish(db, operation_id, outcome, error).await;
                }
            }
        }
        Err(error) => {
            tracing::error!(%app_id, error = %error, "failed to list interrupted switches")
        }
    }
}

#[derive(sqlx::FromRow)]
struct Interrupted {
    operation_id: Uuid,
    operation: String,
    target_deployment_id: Option<Uuid>,
    app_destroyed: bool,
    app_state: String,
    target_status: Option<String>,
    target_cleaned_up: bool,
}

/// Destroys whose request ended without an outcome, and switches of apps
/// destroyed meanwhile (live repair no longer visits them).
pub(crate) async fn settle_interrupted(db: &PgPool) -> Result<usize, SettleError> {
    // Only static SQL fragments are interpolated; runtime values are bound below.
    let rows: Vec<Interrupted> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT r.operation_id, r.operation, r.target_deployment_id,
                cr.destroyed_at IS NOT NULL AS app_destroyed, cr.state::text AS app_state,
                t.status AS target_status, t.cleaned_up_at IS NOT NULL AS target_cleaned_up
         FROM deployment_events r
         JOIN compute_resources cr ON cr.id = r.app_id
         LEFT JOIN app_deployments t ON t.id = r.target_deployment_id AND t.app_id = r.app_id
         WHERE {OPEN_ELSEWHERE}
           AND (r.operation <> 'switch' OR cr.destroyed_at IS NOT NULL)"
    )))
    .bind(*PROCESS_ID)
    .fetch_all(db)
    .await
    .with_context(SettleErrorCtx::database())?;
    let mut settled = 0;
    for row in rows {
        let observation = match row.operation.as_str() {
            "switch" => Observation::AppGone,
            "deployment_destroy" => Observation::Deployment {
                status: row.target_status.as_deref(),
                cleaned_up: row.target_cleaned_up,
            },
            _ => Observation::App {
                destroyed: row.app_destroyed,
                state: &row.app_state,
            },
        };
        if let Some((outcome, error)) = settled_outcome(row.target_deployment_id, observation) {
            finish(db, row.operation_id, outcome, error).await;
            settled += 1;
        }
    }
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_and_outcomes_match_the_schema() {
        assert_eq!(
            [
                Operation::Switch,
                Operation::DeploymentDestroy,
                Operation::AppDestroy
            ]
            .map(Operation::as_str),
            ["switch", "deployment_destroy", "app_destroy"]
        );
        assert_eq!(
            [
                Outcome::Succeeded,
                Outcome::Rejected,
                Outcome::Failed,
                Outcome::Observed
            ]
            .map(Outcome::as_str),
            ["succeeded", "rejected", "failed", "observed"]
        );
    }

    #[test]
    fn interrupted_operations_settle_from_what_reconciliation_observes() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        // Switch: the confirmed EIP holder decides.
        assert!(matches!(
            settled_outcome(Some(b), Observation::Holder(Some(b))),
            Some((Outcome::Observed, None))
        ));
        assert!(matches!(
            settled_outcome(Some(b), Observation::Holder(Some(a))),
            Some((Outcome::Failed, Some(_)))
        ));
        assert!(matches!(
            settled_outcome(Some(b), Observation::Holder(None)),
            Some((Outcome::Failed, Some(_)))
        ));
        assert!(matches!(
            settled_outcome(Some(b), Observation::AppGone),
            Some((Outcome::Failed, Some(_)))
        ));
        // Deployment destroy: wait while it is destroying or its cleanup is retried.
        let deployment = |status, cleaned_up| Observation::Deployment {
            status: Some(status),
            cleaned_up,
        };
        assert!(matches!(
            settled_outcome(Some(b), deployment("destroyed", true)),
            Some((Outcome::Observed, None))
        ));
        assert!(settled_outcome(Some(b), deployment("destroying", false)).is_none());
        assert!(settled_outcome(Some(b), deployment("failed", false)).is_none());
        assert!(matches!(
            settled_outcome(Some(b), deployment("running", false)),
            Some((Outcome::Failed, Some(_)))
        ));
        // App destroy: wait while the teardown loop still runs.
        assert!(matches!(
            settled_outcome(
                None,
                Observation::App {
                    destroyed: true,
                    state: "terminated"
                }
            ),
            Some((Outcome::Observed, None))
        ));
        assert!(
            settled_outcome(
                None,
                Observation::App {
                    destroyed: false,
                    state: "terminating"
                }
            )
            .is_none()
        );
        assert!(matches!(
            settled_outcome(
                None,
                Observation::App {
                    destroyed: false,
                    state: "running"
                }
            ),
            Some((Outcome::Failed, Some(_)))
        ));
    }

    #[test]
    fn stored_errors_are_bounded_single_line_summaries() {
        assert_eq!(safe_error("Busy\nretry"), "Busyretry");
        assert_eq!(safe_error(&"x".repeat(400)).len(), 300);
    }
}

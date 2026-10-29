// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! App deployments (blue-green) for apps on the `deployments` lifecycle.

pub(crate) mod account;
pub(crate) mod admission;
pub(crate) mod destroy;
pub(crate) mod events;
pub(crate) mod handlers;
pub(crate) mod history;
pub(crate) mod internal;
pub(crate) mod lifecycle;
pub(crate) mod reconcile;
pub(crate) mod summary;
pub(crate) mod switch;

use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::LazyLock;
use uuid::Uuid;

/// Identifies this API process. The API runs as a single process whose
/// OpenTofu children stop with it, so work owned by another process ID was
/// abandoned by a restart. Running several API replicas requires leases first.
pub(crate) static PROCESS_ID: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

pub(crate) const LIFECYCLE_DEPLOYMENTS: &str = "deployments";
pub(crate) const LIFECYCLE_LEGACY: &str = "legacy";
const DEFAULT_MAX_CANDIDATES: i64 = 3;

/// Failure modes for [`parse_max_candidates`] (source-less leaf error).
#[derive(Debug, thiserror::Error)]
pub(crate) enum MaxCandidatesError {
    #[error("MAX_CANDIDATES_PER_APP must be a positive integer, got {value:?} [{location}]")]
    Invalid { value: String, location: Location },
}

pub(crate) fn parse_max_candidates(value: Option<&str>) -> Result<i64, MaxCandidatesError> {
    let Some(value) = value else {
        return Ok(DEFAULT_MAX_CANDIDATES);
    };
    match value.trim().parse::<i64>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => Err(MaxCandidatesError::Invalid {
            value: value.to_string(),
            location: std::panic::Location::caller(),
        }),
    }
}

/// Validated at startup (see `main`), so the fallback is never reached in practice.
pub(crate) fn max_candidates_per_app() -> i64 {
    parse_max_candidates(std::env::var("MAX_CANDIDATES_PER_APP").ok().as_deref())
        .unwrap_or(DEFAULT_MAX_CANDIDATES)
}

pub(crate) fn enabled_for_new_apps() -> bool {
    std::env::var("APP_DEPLOYMENTS_ENABLED").is_ok_and(|value| value.trim() == "true")
}

/// `APP_DEPLOYMENTS_BYOC_ENABLED`: new BYOC apps (`caution init --byoc`) get the
/// deployments lifecycle. Apart from the managed flag, so each mode is released
/// on its own.
pub(crate) fn byoc_enabled_for_new_apps() -> bool {
    std::env::var("APP_DEPLOYMENTS_BYOC_ENABLED").is_ok_and(|value| value.trim() == "true")
}

/// The lifecycle of a new app: `deployments` only when its mode's flag is on.
pub(crate) fn lifecycle_for_new_app(enabled: bool) -> &'static str {
    if enabled {
        LIFECYCLE_DEPLOYMENTS
    } else {
        LIFECYCLE_LEGACY
    }
}

/// Failure modes for [`assign_byoc_lifecycle`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to assign the BYOC lifecycle of app {app_id} [{location}]")]
pub(crate) struct AssignByocLifecycleError {
    app_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// The first BYOC link of a pristine app is BYOC app creation: interactive
/// `caution init --byoc` creates the app through `POST /resources` (which
/// follows the managed flag), then links it. Sets the lifecycle the BYOC flag
/// (`byoc_enabled`) gives a new app, only while the app is initialized, has no
/// region, network, deployment or BYOC credential. Returns whether the app was
/// pristine (and its lifecycle assigned); any other link keeps the lifecycle.
pub(crate) async fn assign_byoc_lifecycle(
    db: &PgPool,
    app_id: Uuid,
    byoc_enabled: bool,
) -> Result<bool, AssignByocLifecycleError> {
    sqlx::query(
        "UPDATE compute_resources cr SET lifecycle = $2
         WHERE cr.id = $1 AND cr.destroyed_at IS NULL AND cr.state = 'initialized'
           AND cr.region IS NULL AND cr.app_network IS NULL
           AND NOT EXISTS (SELECT 1 FROM app_deployments d WHERE d.app_id = cr.id)
           AND NOT EXISTS (
               SELECT 1 FROM cloud_credentials c WHERE c.resource_id = cr.id AND c.managed_on_prem
           )",
    )
    .bind(app_id)
    .bind(lifecycle_for_new_app(byoc_enabled))
    .execute(db)
    .await
    .map(|result| result.rows_affected() == 1)
    .with_context(AssignByocLifecycleErrorCtx::new(app_id))
}

/// Failure modes for [`lock_app_operations`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
#[error("failed to lock deployment operations for app {app_id}")]
pub(crate) struct LockAppOperationsError {
    app_id: Uuid,
    #[provide]
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// Serializes reservation, activation, switch and deployment destruction per
/// app. Namespace 2 keeps it apart from the teardown lock (namespace 1).
pub(crate) async fn lock_app_operations(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
) -> Result<(), LockAppOperationsError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(app_id.to_string())
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .with_context(LockAppOperationsErrorCtx::new(app_id))
}

/// Failure modes for [`app_lifecycle`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to read the lifecycle of app {app_id} [{location}]")]
pub(crate) struct AppLifecycleError {
    app_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

pub(crate) async fn app_lifecycle(
    db: &PgPool,
    app_id: Uuid,
) -> Result<Option<String>, AppLifecycleError> {
    sqlx::query_scalar("SELECT lifecycle FROM compute_resources WHERE id = $1")
        .bind(app_id)
        .fetch_optional(db)
        .await
        .with_context(AppLifecycleErrorCtx::new(app_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_apps_are_legacy_unless_the_flag_is_on() {
        assert_eq!(lifecycle_for_new_app(false), "legacy");
        assert_eq!(lifecycle_for_new_app(true), "deployments");
    }

    #[test]
    fn max_candidates_defaults_to_three() {
        assert_eq!(parse_max_candidates(None).unwrap(), 3);
    }

    #[test]
    fn max_candidates_accepts_positive_integers() {
        assert_eq!(parse_max_candidates(Some("1")).unwrap(), 1);
        assert_eq!(parse_max_candidates(Some(" 5 ")).unwrap(), 5);
    }

    #[test]
    fn max_candidates_rejects_zero_negative_and_garbage() {
        for value in ["0", "-1", "three", ""] {
            assert!(
                parse_max_candidates(Some(value)).is_err(),
                "{value:?} must be rejected"
            );
        }
    }
}

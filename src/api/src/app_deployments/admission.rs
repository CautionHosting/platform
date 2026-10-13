// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{LIFECYCLE_DEPLOYMENTS, PROCESS_ID, lock_app_operations, max_candidates_per_app};
use axum::http::StatusCode;
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum Admission {
    Accept,
    Busy,
    LimitReached { candidates: i64, limit: i64 },
}

/// The only push-state rule: `reserve` applies it under the app lock before
/// the gateway runs `receive-pack`, and `claim_for_build` re-applies it.
pub(crate) fn deployments_push_state_allowed(state: &str) -> bool {
    matches!(state, "initialized" | "running" | "failed" | "terminated")
}

pub(crate) fn admission_decision(active_operation: bool, candidates: i64, limit: i64) -> Admission {
    if active_operation {
        Admission::Busy
    } else if candidates >= limit {
        Admission::LimitReached { candidates, limit }
    } else {
        Admission::Accept
    }
}

/// Failure modes for [`reserve`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReserveError {
    #[error("app {app_id} not found [{location}]")]
    NotFound { app_id: Uuid, location: Location },
    #[error("app {app_id} does not use the deployments lifecycle [{location}]")]
    NotDeploymentsLifecycle { app_id: Uuid, location: Location },
    #[error("app {app_id} is {state} and cannot accept a push [{location}]")]
    NotPushable {
        app_id: Uuid,
        state: String,
        location: Location,
    },
    #[error("a build or provisioning operation is already running for app {app_id} [{location}]")]
    Busy { app_id: Uuid, location: Location },
    #[error("app {app_id} has {candidates} of {limit} candidates [{location}]")]
    LimitReached {
        app_id: Uuid,
        candidates: i64,
        limit: i64,
        location: Location,
    },
    #[error("failed to lock app operations [{location}]")]
    Lock {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("database error while reserving a deployment [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl ReserveError {
    /// Fixed client-facing text; the gateway prints it on the git channel.
    pub(crate) fn client_response(&self) -> (StatusCode, String) {
        match self {
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "App not found.".to_string()),
            Self::NotDeploymentsLifecycle { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "This app does not use deployments.".to_string(),
            ),
            Self::NotPushable { state, .. } => (
                StatusCode::CONFLICT,
                format!("This app is {state} and cannot accept a push right now."),
            ),
            Self::Busy { .. } => (
                StatusCode::CONFLICT,
                "Another build or provisioning operation is running for this app. Retry once it finishes."
                    .to_string(),
            ),
            Self::LimitReached {
                candidates, limit, ..
            } => (
                StatusCode::CONFLICT,
                format!(
                    "Candidate limit reached ({candidates} / {limit}). Destroy a candidate with `caution apps destroy -d <id>` before pushing again."
                ),
            ),
            Self::Lock { .. } | Self::Database { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to reserve a deployment.".to_string(),
            ),
        }
    }
}

/// Reserves a candidate slot and the app's single build/provisioning
/// operation before the gateway accepts a ref update.
pub(crate) async fn reserve(
    db: &PgPool,
    org_id: Uuid,
    app_id: Uuid,
    user_id: Uuid,
) -> Result<Uuid, ReserveError> {
    use ReserveErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::lock())?;

    let app: Option<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT lifecycle, state::text, live_deployment_id FROM compute_resources
         WHERE id = $1 AND organization_id = $2
         FOR UPDATE",
    )
    .bind(app_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    let Some((lifecycle, state, live_deployment_id)) = app else {
        return Err(ReserveError::NotFound {
            app_id,
            location: std::panic::Location::caller(),
        });
    };
    if lifecycle != LIFECYCLE_DEPLOYMENTS {
        return Err(ReserveError::NotDeploymentsLifecycle {
            app_id,
            location: std::panic::Location::caller(),
        });
    }
    // Under the app lock, so a suspend or destroy racing the push never gets
    // a reservation. The gateway relays this 409 before `receive-pack`.
    if !deployments_push_state_allowed(&state) {
        return Err(ReserveError::NotPushable {
            app_id,
            state,
            location: std::panic::Location::caller(),
        });
    }

    // A push that died before binding (gateway restart, dropped SSH session)
    // must not keep the app busy until the reconciler runs.
    sqlx::query(
        "DELETE FROM app_deployments
         WHERE app_id = $1 AND status = 'reserved' AND reservation_expires_at < NOW()",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::database())?;

    let (active_operation, candidates): (bool, i64) = sqlx::query_as(
        "SELECT
             EXISTS (SELECT 1 FROM app_deployments
                     WHERE app_id = $1 AND status IN ('reserved', 'building', 'provisioning')),
             (SELECT COUNT(*) FROM app_deployments
              WHERE app_id = $1 AND id IS DISTINCT FROM $2
                AND (status IN ('reserved', 'building', 'provisioning', 'running', 'destroying')
                     OR (status = 'failed' AND cleaned_up_at IS NULL)))",
    )
    .bind(app_id)
    .bind(live_deployment_id)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::database())?;

    let limit = max_candidates_per_app();
    match admission_decision(active_operation, candidates, limit) {
        Admission::Accept => {}
        Admission::Busy => {
            return Err(ReserveError::Busy {
                app_id,
                location: std::panic::Location::caller(),
            });
        }
        Admission::LimitReached { candidates, limit } => {
            return Err(ReserveError::LimitReached {
                app_id,
                candidates,
                limit,
                location: std::panic::Location::caller(),
            });
        }
    }

    let deployment_id: Uuid = sqlx::query_scalar(
        "INSERT INTO app_deployments (app_id, organization_id, pushed_by, reservation_expires_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '30 minutes')
         RETURNING id",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;
    Ok(deployment_id)
}

/// Failure modes for [`release_reservation`].
#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to release deployment reservation {deployment_id} [{location}]")]
pub(crate) struct ReleaseReservationError {
    deployment_id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// Releases a reservation that never became a deployment (no-op, multiple-ref
/// or failed push, or a deploy rejected before its claim). A claimed
/// deployment is unaffected. Idempotent.
///
/// `app_id` scopes the release to that app's reservations. Only the internal
/// release route passes `None`: the gateway is trusted (internal service
/// secret) and that route carries no app ID.
pub(crate) async fn release_reservation(
    db: &PgPool,
    deployment_id: Uuid,
    app_id: Option<Uuid>,
) -> Result<(), ReleaseReservationError> {
    sqlx::query(
        "DELETE FROM app_deployments
         WHERE id = $1 AND ($2::uuid IS NULL OR app_id = $2) AND status = 'reserved'",
    )
    .bind(deployment_id)
    .bind(app_id)
    .execute(db)
    .await
    .map(|_| ())
    .with_context(ReleaseReservationErrorCtx::new(deployment_id))
}

/// Failure to release the reservations left by the previous process.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReleaseStaleReservationsError {
    #[error("database error while releasing stale deployment reservations [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Deletes every `reserved` row and returns how many. Run once at startup: the
/// API is a single process, so no reservation can belong to a live request.
/// Same release as [`release_reservation`]: claimed (`building` or later)
/// deployments are never touched.
pub(crate) async fn release_stale_reservations(
    db: &PgPool,
) -> Result<u64, ReleaseStaleReservationsError> {
    sqlx::query("DELETE FROM app_deployments WHERE status = 'reserved'")
        .execute(db)
        .await
        .map(|result| result.rows_affected())
        .with_context(ReleaseStaleReservationsErrorCtx::database())
}

/// Failure modes for [`claim_for_build`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ClaimError {
    #[error(
        "deployment {deployment_id} is no longer reserved for app {app_id}; push again [{location}]"
    )]
    ReservationGone {
        app_id: Uuid,
        deployment_id: Uuid,
        location: Location,
    },
    #[error("app {app_id} is {state} and cannot start a build [{location}]")]
    NotPushable {
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
    #[error("database error while claiming deployment [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Binds the pushed ref/SHA to the reservation and takes ownership for this
/// process. A destroyed app is reactivated, as Legacy does on redeploy.
pub(crate) async fn claim_for_build(
    db: &PgPool,
    app_id: Uuid,
    deployment_id: Uuid,
    branch: &str,
    commit_sha: &str,
    commit_subject: Option<&str>,
    bundle_hash: Option<&str>,
) -> Result<(), ClaimError> {
    use ClaimErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::database())?;
    lock_app_operations(&mut tx, app_id)
        .await
        .with_context(Ctx::lock())?;
    // Suspension does not take the app lock, so re-check the state here.
    let state: String =
        sqlx::query_scalar("SELECT state::text FROM compute_resources WHERE id = $1 FOR UPDATE")
            .bind(app_id)
            .fetch_one(&mut *tx)
            .await
            .with_context(Ctx::database())?;
    if !deployments_push_state_allowed(&state) {
        return Err(ClaimError::NotPushable {
            app_id,
            state,
            location: std::panic::Location::caller(),
        });
    }
    let claimed = sqlx::query(
        "UPDATE app_deployments
         SET status = 'building', pushed_ref = $3, commit_sha = $4, commit_subject = $5,
             owner_process_id = $6, reservation_expires_at = NULL, bundle_hash = $7
         WHERE id = $1 AND app_id = $2 AND status = 'reserved' AND reservation_expires_at > NOW()",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(branch)
    .bind(commit_sha)
    .bind(commit_subject)
    .bind(*PROCESS_ID)
    .bind(bundle_hash)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    if claimed.rows_affected() == 0 {
        return Err(ClaimError::ReservationGone {
            app_id,
            deployment_id,
            location: std::panic::Location::caller(),
        });
    }
    sqlx::query(
        "UPDATE compute_resources SET destroyed_at = NULL, state = 'initialized'
         WHERE id = $1 AND destroyed_at IS NOT NULL",
    )
    .bind(app_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;
    Ok(())
}

/// Best effort: the commit subject is display metadata only. Control
/// characters are stripped because the subject is echoed to terminals.
pub(crate) async fn commit_subject(git_dir: &str, commit_sha: &str) -> Option<String> {
    let output = tokio::process::Command::new("git")
        .args(["--git-dir", git_dir, "log", "-1", "--format=%s", commit_sha])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let subject: String = String::from_utf8_lossy(&output.stdout)
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    (!subject.is_empty()).then_some(subject)
}

/// The documented source of the bundle an app copies into its image
/// (`COPY .caution/quorum-bundle.json /etc/caution/bundle.json`).
const DEPLOYED_BUNDLE_PATH: &str = ".caution/quorum-bundle.json";

/// Best effort: the canonical hash of the bundle committed at `commit_sha`.
/// `None` when the source has none or it does not parse; share release to
/// this deployment then requires an explicit, operator-chosen bundle.
pub(crate) async fn deployed_bundle_hash(git_dir: &str, commit_sha: &str) -> Option<String> {
    let output = tokio::process::Command::new("git")
        .args([
            "--git-dir",
            git_dir,
            "show",
            &format!("{commit_sha}:{DEPLOYED_BUNDLE_PATH}"),
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let data: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    crate::cryptographic_bundles::canonical_hash(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_reports_busy_before_limit() {
        assert!(matches!(admission_decision(true, 3, 3), Admission::Busy));
        assert!(matches!(admission_decision(true, 0, 3), Admission::Busy));
    }

    #[test]
    fn admission_rejects_at_and_above_limit() {
        assert!(matches!(
            admission_decision(false, 3, 3),
            Admission::LimitReached {
                candidates: 3,
                limit: 3
            }
        ));
        // Lowering the cap keeps existing candidates but blocks new ones.
        assert!(matches!(
            admission_decision(false, 3, 1),
            Admission::LimitReached {
                candidates: 3,
                limit: 1
            }
        ));
    }

    #[test]
    fn admission_accepts_below_limit() {
        assert!(matches!(admission_decision(false, 2, 3), Admission::Accept));
    }

    #[test]
    fn deployments_push_rejects_stopped_terminating_and_pending() {
        for state in ["initialized", "running", "failed", "terminated"] {
            assert!(deployments_push_state_allowed(state), "{state}");
        }
        for state in ["stopped", "terminating", "pending"] {
            assert!(!deployments_push_state_allowed(state), "{state}");
        }
    }

    /// The canonical-hash fixture of `cryptographic_bundles::identity_tests`.
    const BUNDLE: &str = r#"{"data":{"version":"V1","bundle_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"label":{"a":"1","b":"2"},"keyring":[],"threshold":1,"max":1,"shardfile":"shares","public_key":"key"},"necroproof":[]}"#;

    #[tokio::test]
    async fn deployed_bundle_hash_reads_the_bundle_at_the_exact_commit() {
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .current_dir(repo.path())
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "test"]);
        git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.path().join("README"), "app").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "no bundle"]);
        let without = git(&["rev-parse", "HEAD"]);
        // Only the documented image input counts; the CLI's download cache does not.
        std::fs::create_dir_all(repo.path().join(".caution/secrets")).unwrap();
        std::fs::write(repo.path().join(".caution/secrets/bundle.json"), BUNDLE).unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "cached download only"]);
        let cached_only = git(&["rev-parse", "HEAD"]);
        std::fs::write(repo.path().join(".caution/quorum-bundle.json"), BUNDLE).unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "bundle"]);
        let with_bundle = git(&["rev-parse", "HEAD"]);

        let git_dir = repo.path().join(".git");
        let git_dir = git_dir.to_str().unwrap();
        let expected =
            crate::cryptographic_bundles::canonical_hash(&serde_json::from_str(BUNDLE).unwrap());
        // The literal the CLI's `send_shard_tests` pins: a change on either side fails a test.
        assert_eq!(
            expected.as_deref(),
            Some("0331123d7171622a4a4440ff3916f9d85e99199a7e146388fac2fe3e5ca79ae3")
        );
        assert_eq!(deployed_bundle_hash(git_dir, &with_bundle).await, expected);
        assert_eq!(deployed_bundle_hash(git_dir, &cached_only).await, None);
        // An earlier commit does not inherit a later bundle.
        assert_eq!(deployed_bundle_hash(git_dir, &without).await, None);
        assert_eq!(
            deployed_bundle_hash(git_dir, "0000000000000000000000000000000000000000").await,
            None
        );
    }
}

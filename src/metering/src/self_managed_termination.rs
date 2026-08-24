// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

const TERMINATION_BATCH_SIZE: usize = 16;
const MAX_TERMINATION_ATTEMPTS: i32 = 12;

pub async fn run_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        for _ in 0..TERMINATION_BATCH_SIZE {
            match run_one(&state).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    tracing::error!(error = %error, "self-managed termination worker failed");
                    break;
                }
            }
        }
    }
}

async fn run_one(state: &AppState) -> anyhow::Result<bool> {
    reconcile_one_canceled_subscription(state).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE self_managed_termination_jobs
         SET status = 'retry', lease_expires_at = NULL, lease_token = NULL,
             next_attempt_at = NOW(), updated_at = NOW()
         WHERE status = 'processing' AND lease_expires_at < NOW()",
    )
    .execute(&mut *tx)
    .await?;
    let job: Option<(Uuid, Uuid, Uuid, i32, Uuid)> = sqlx::query_as(
        "WITH candidate AS (
             SELECT j.id FROM self_managed_termination_jobs j
             WHERE j.status IN ('pending', 'retry') AND j.next_attempt_at <= NOW()
             ORDER BY j.created_at
             FOR UPDATE SKIP LOCKED LIMIT 1
         )
         UPDATE self_managed_termination_jobs j
         SET status = 'processing', attempt_count = j.attempt_count + 1,
             lease_expires_at = NOW() + INTERVAL '35 minutes',
             lease_token = gen_random_uuid(), updated_at = NOW()
         FROM candidate, self_managed_plans p
         WHERE j.id = candidate.id AND p.id = j.self_managed_plan_id
         RETURNING j.id, p.organization_id, j.resource_id, j.attempt_count, j.lease_token",
    )
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let Some((job_id, org_id, resource_id, attempt_count, lease_token)) = job else {
        return Ok(false);
    };

    let result = call_api(state, job_id, resource_id, lease_token).await;

    match result {
        Ok(()) => {
            let updated = sqlx::query(
                "UPDATE self_managed_termination_jobs
                 SET status = 'completed', completed_at = NOW(), lease_expires_at = NULL,
                     lease_token = NULL, last_error = NULL, updated_at = NOW()
                 WHERE id = $1 AND status = 'processing' AND lease_token = $2",
            )
            .bind(job_id)
            .bind(lease_token)
            .execute(&state.pool)
            .await?
            .rows_affected();
            anyhow::ensure!(
                updated == 1,
                "termination job lease changed before completion"
            );
        }
        Err(error) => {
            let dead_letter = error.permanent || attempt_count >= MAX_TERMINATION_ATTEMPTS;
            let delay_seconds = i64::from(2_i32.saturating_pow(attempt_count.min(10) as u32)) * 30;
            let updated = sqlx::query(
                "UPDATE self_managed_termination_jobs
                 SET status = CASE WHEN $2 THEN 'dead_letter' ELSE 'retry' END,
                     lease_expires_at = NULL, lease_token = NULL,
                     next_attempt_at = CASE WHEN $2 THEN next_attempt_at
                                            ELSE NOW() + make_interval(secs => $3) END,
                     last_error = left($4, 2000), updated_at = NOW()
                 WHERE id = $1 AND status = 'processing' AND lease_token = $5",
            )
            .bind(job_id)
            .bind(dead_letter)
            .bind(delay_seconds)
            .bind(&error.message)
            .bind(lease_token)
            .execute(&state.pool)
            .await?
            .rows_affected();
            anyhow::ensure!(
                updated == 1,
                "termination job lease changed before failure recording"
            );
            if dead_letter {
                tracing::error!(
                    %job_id,
                    %org_id,
                    %resource_id,
                    attempt_count,
                    error = %error.message,
                    "self-managed termination job moved to dead letter"
                );
            }
        }
    }
    Ok(true)
}

/// Finish the authority cutover if an older metering instance projected a
/// cancellation only into `subscriptions` during a rolling deployment.
async fn reconcile_one_canceled_subscription(state: &AppState) -> anyhow::Result<()> {
    let candidate: Option<(Uuid, Uuid, Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT s.id, s.organization_id, s.self_managed_plan_id,
                COALESCE(s.provider_occurred_at, s.canceled_at, s.updated_at)
         FROM subscriptions s
         JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
                                  AND p.organization_id = s.organization_id
         WHERE s.billing_source = 'paddle' AND s.status = 'canceled'
           AND p.source = 'paddle'
         ORDER BY s.updated_at LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await?;
    let Some((subscription_id, organization_id, plan_id, occurred_at)) = candidate else {
        return Ok(());
    };

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *tx)
        .await?;
    // Preserve the rolling trigger's subscription -> plan lock order so an old
    // subscription writer cannot deadlock this reconciler.
    let locked_subscription: Option<Uuid> = sqlx::query_scalar(
        "SELECT self_managed_plan_id FROM subscriptions
         WHERE id = $1 AND organization_id = $2
           AND self_managed_plan_id = $3
           AND status = 'canceled' AND billing_source = 'paddle'
         FOR UPDATE",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(plan_id)
    .fetch_optional(&mut *tx)
    .await?;
    if locked_subscription.is_none() {
        tx.commit().await?;
        return Ok(());
    }
    let locked_plan: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM self_managed_plans
         WHERE id = $1 AND organization_id = $2 AND source = 'paddle'
         FOR UPDATE",
    )
    .bind(plan_id)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?;
    if locked_plan.is_none() {
        tx.commit().await?;
        return Ok(());
    }

    let manual_change: Option<(
        Uuid,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, requested_enclave_limit, requested_expires_at,
                operator_identity, operator_reason
         FROM self_managed_plan_changes
         WHERE organization_id = $1 AND subscription_id = $2
           AND status = 'provider_pending'
         ORDER BY created_at LIMIT 1 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(subscription_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((change_id, limit, expires_at, operator, reason)) = manual_change {
        sqlx::query(
            "UPDATE self_managed_plans
             SET tier = 'enterprise_contract', enclave_limit = $1,
                 source = 'manual', expires_at = $2,
                 operator_identity = $3, operator_reason = $4,
                 terminated_at = NULL, updated_at = NOW()
             WHERE id = $5 AND organization_id = $6 AND source = 'paddle'",
        )
        .bind(limit)
        .bind(expires_at)
        .bind(operator)
        .bind(reason)
        .bind(plan_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE subscriptions SET self_managed_plan_id = NULL, updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND self_managed_plan_id = $3",
        )
        .bind(subscription_id)
        .bind(organization_id)
        .bind(plan_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE self_managed_plan_changes
             SET status = 'applied', applied_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND status = 'provider_pending'",
        )
        .bind(change_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(());
    }

    sqlx::query(
        "UPDATE self_managed_plans
         SET enclave_limit = 0, terminated_at = COALESCE(terminated_at, $1),
             updated_at = NOW()
         WHERE id = $2 AND organization_id = $3 AND source = 'paddle'",
    )
    .bind(occurred_at)
    .bind(plan_id)
    .bind(organization_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO self_managed_termination_jobs
            (organization_id, self_managed_plan_id, subscription_id,
             resource_id, provider_occurred_at)
         SELECT $1, $2, $3, cr.id, $4
         FROM compute_resources cr
         WHERE cr.organization_id = $1 AND cr.destroyed_at IS NULL
           AND EXISTS (
               SELECT 1 FROM cloud_credentials cc
               WHERE cc.resource_id = cr.id AND cc.organization_id = $1
                 AND cc.managed_on_prem = true
           )
         ON CONFLICT (subscription_id, resource_id) DO NOTHING",
    )
    .bind(organization_id)
    .bind(plan_id)
    .bind(subscription_id)
    .bind(occurred_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE subscriptions SET self_managed_plan_id = NULL, updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND self_managed_plan_id = $3",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(plan_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug)]
struct ApiCallError {
    message: String,
    permanent: bool,
}

fn is_permanent_api_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::BAD_REQUEST
            | reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::UNPROCESSABLE_ENTITY
    )
}

async fn call_api(
    state: &AppState,
    job_id: Uuid,
    resource_id: Uuid,
    lease_token: Uuid,
) -> Result<(), ApiCallError> {
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1_800))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| ApiCallError {
            message: error.to_string(),
            permanent: false,
        })?
        .post(format!(
            "{}/internal/self-managed-termination-jobs/{}/resources/{}/terminate",
            api_url, job_id, resource_id
        ))
        .header("x-internal-service-secret", &state.internal_service_secret)
        .header("x-termination-lease-token", lease_token.to_string())
        .send()
        .await
        .map_err(|error| ApiCallError {
            message: error.to_string(),
            permanent: false,
        })?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ApiCallError {
            message: format!("API returned {status}"),
            permanent: is_permanent_api_status(status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TERMINATION_ATTEMPTS, is_permanent_api_status};
    use reqwest::StatusCode;

    #[test]
    fn retry_backoff_is_bounded() {
        let attempt_count = 100_i32;
        let seconds = i64::from(2_i32.saturating_pow(attempt_count.min(10) as u32)) * 30;
        assert_eq!(seconds, 30_720);
    }

    #[test]
    fn authentication_and_validation_failures_are_permanent() {
        assert!(is_permanent_api_status(StatusCode::BAD_REQUEST));
        assert!(is_permanent_api_status(StatusCode::UNAUTHORIZED));
        assert!(is_permanent_api_status(StatusCode::FORBIDDEN));
        assert!(is_permanent_api_status(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[test]
    fn rolling_and_concurrency_failures_remain_retryable() {
        assert!(!is_permanent_api_status(StatusCode::NOT_FOUND));
        assert!(!is_permanent_api_status(StatusCode::CONFLICT));
        assert!(!is_permanent_api_status(StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn service_and_timeout_failures_remain_retryable() {
        assert!(!is_permanent_api_status(StatusCode::BAD_GATEWAY));
        assert!(!is_permanent_api_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!is_permanent_api_status(StatusCode::REQUEST_TIMEOUT));
        assert_eq!(MAX_TERMINATION_ATTEMPTS, 12);
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

pub async fn run_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        if let Err(error) = run_one(&state).await {
            tracing::error!(error = %error, "self-managed termination worker failed");
        }
    }
}

async fn run_one(state: &AppState) -> anyhow::Result<()> {
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
    let Some((job_id, _org_id, resource_id, attempt_count, lease_token)) = job else {
        return Ok(());
    };

    let result = call_api(state, job_id, resource_id, lease_token).await;

    match result {
        Ok(()) => {
            sqlx::query(
                "UPDATE self_managed_termination_jobs
                 SET status = 'completed', completed_at = NOW(), lease_expires_at = NULL,
                     lease_token = NULL, last_error = NULL, updated_at = NOW()
                 WHERE id = $1 AND status = 'processing' AND lease_token = $2",
            )
            .bind(job_id)
            .bind(lease_token)
            .execute(&state.pool)
            .await?;
        }
        Err(error) => {
            let delay_seconds = i64::from(2_i32.saturating_pow(attempt_count.min(10) as u32)) * 30;
            sqlx::query(
                "UPDATE self_managed_termination_jobs
                 SET status = 'retry', lease_expires_at = NULL, lease_token = NULL,
                     next_attempt_at = NOW() + make_interval(secs => $2),
                     last_error = left($3, 2000), updated_at = NOW()
                 WHERE id = $1 AND status = 'processing' AND lease_token = $4",
            )
            .bind(job_id)
            .bind(delay_seconds)
            .bind(error)
            .bind(lease_token)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(())
}

async fn call_api(
    state: &AppState,
    job_id: Uuid,
    resource_id: Uuid,
    lease_token: Uuid,
) -> Result<(), String> {
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(1_800))
        .build()
        .map_err(|e| e.to_string())?
        .post(format!(
            "{}/internal/self-managed-termination-jobs/{}/resources/{}/terminate",
            api_url, job_id, resource_id
        ))
        .header("x-internal-service-secret", &state.internal_service_secret)
        .header("x-termination-lease-token", lease_token.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("API returned {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retry_backoff_is_bounded() {
        let attempt_count = 100_i32;
        let seconds = i64::from(2_i32.saturating_pow(attempt_count.min(10) as u32)) * 30;
        assert_eq!(seconds, 30_720);
    }
}

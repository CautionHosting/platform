// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::AppState;
use crate::types::*;
use crate::balance::check_balance_thresholds;

// Advisory lock IDs for distributed coordination
pub(crate) const LOCK_COLLECTION: i64 = 1001;
pub(crate) const LOCK_MONTHLY_BILLING: i64 = 1002;
pub(crate) const LOCK_SUBSCRIPTION_BILLING: i64 = 1003;

/// Try to acquire an advisory lock, run the closure, and release the lock.
/// Returns None if the lock is already held by another instance.
pub(crate) async fn try_advisory_lock(pool: &sqlx::PgPool, lock_id: i64) -> bool {
    sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(pool)
        .await
        .unwrap_or(false)
}

pub(crate) async fn advisory_unlock(pool: &sqlx::PgPool, lock_id: i64) {
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(pool)
        .await;
}

pub async fn trigger_collection(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Bypass advisory lock for explicitly triggered collections — the lock only
    // prevents duplicate background loop runs, not manual API invocations.
    match run_collection_cycle_inner(&state).await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({"collected": count}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

pub async fn run_collection_loop(state: Arc<AppState>, interval_secs: u64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        if let Err(e) = run_collection_cycle(&state).await {
            tracing::error!("Metering collection failed: {}", e);
        }
    }
}

async fn run_collection_cycle(state: &AppState) -> Result<usize> {
    if !try_advisory_lock(&state.pool, LOCK_COLLECTION).await {
        tracing::debug!("Collection cycle skipped — another instance holds the lock");
        return Ok(0);
    }
    let result = run_collection_cycle_inner(state).await;
    advisory_unlock(&state.pool, LOCK_COLLECTION).await;
    result
}

pub(crate) async fn run_collection_cycle_inner(state: &AppState) -> Result<usize> {
    tracing::info!("Running metering collection cycle");

    let resources = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut collected = 0;
    let mut users_with_deductions = HashSet::new();

    for resource in &resources {
        match collect_resource_usage(state, &resource.resource_id).await {
            Ok(true) => {
                collected += 1;
                users_with_deductions.insert(resource.user_id);
            }
            Ok(false) => {
                collected += 1;
            }
            Err(e) => {
                tracing::error!("Failed to collect usage for {}: {}", resource.resource_id, e);
            }
        }
    }

    // After all resources processed: check balance thresholds per user
    for user_id in users_with_deductions {
        if let Err(e) = check_balance_thresholds(state, user_id).await {
            tracing::error!("Failed to check balance thresholds for {}: {}", user_id, e);
        }
    }

    tracing::info!("Collected usage for {} resources", collected);
    Ok(collected)
}

/// Collect usage for a resource and deduct credits in real-time.
/// Returns Ok(true) if a credit deduction occurred, Ok(false) if usage was recorded
/// but no deduction was needed (e.g. zero cost).
pub(crate) async fn collect_resource_usage(state: &AppState, resource_id: &str) -> Result<bool> {
    let resource = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE resource_id = $1
        "#,
    )
    .bind(resource_id)
    .fetch_optional(&state.pool)
    .await?
    .context("Resource not found")?;

    let now = time::OffsetDateTime::now_utc();
    let last_billed = resource.last_billed_at;

    // Calculate hours since last billing using unix timestamps
    let now_unix = now.unix_timestamp();
    let last_billed_unix = last_billed.unix_timestamp();
    let seconds_elapsed = (now_unix - last_billed_unix) as f64;
    let hours = seconds_elapsed / 3600.0;

    if hours < 0.01 {
        // Less than ~36 seconds, skip
        return Ok(false);
    }

    let provider: Provider = resource.provider.parse().unwrap_or(Provider::Aws);

    let usage = ResourceUsage {
        user_id: resource.user_id,
        resource_id: resource.resource_id.clone(),
        provider,
        resource_type: ResourceType::Compute,
        quantity: hours,
        unit: UsageUnit::Hours,
        timestamp: now,
        metadata: serde_json::json!({
            "instance_type": resource.instance_type,
            "region": resource.region,
        }),
    };

    let cost = state.calculator.calculate_cost(&usage);

    // Record locally
    sqlx::query(
        r#"
        INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(usage.user_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(cost)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await?;

    // Update last_billed_at
    sqlx::query(r#"UPDATE tracked_resources SET last_billed_at = $1 WHERE resource_id = $2"#)
        .bind(now)
        .bind(resource_id)
        .execute(&state.pool)
        .await?;

    tracing::debug!(
        "Recorded usage for {}: {:.4} hours, ${:.4}",
        resource_id, hours, cost
    );

    // Real-time credit deduction
    let cost_cents = (cost * 100.0).round() as i64;
    if cost_cents > 0 {
        let (_applied, _remainder, _new_balance) = crate::credits::deduct_realtime_usage(
            &state.pool, resource.user_id, cost_cents, resource_id, hours
        ).await?;
        return Ok(true);
    }

    Ok(false)
}

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::balance::check_balance_thresholds;
use crate::types::*;
use crate::AppState;

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

pub async fn trigger_collection(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Bypass advisory lock for explicitly triggered collections — the lock only
    // prevents duplicate background loop runs, not manual API invocations.
    match run_collection_cycle_inner(&state).await {
        Ok(count) => (
            StatusCode::OK,
            Json(serde_json::json!({"collected": count})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
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

    // Reconcile: stop tracking resources that have been destroyed in compute_resources
    let reconciled = sqlx::query(
        r#"
        UPDATE tracked_resources tr
        SET status = 'stopped', stopped_at = NOW()
        WHERE tr.status = 'running'
          AND tr.application_id IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM compute_resources cr
              WHERE cr.id = tr.application_id
                AND (cr.destroyed_at IS NOT NULL OR cr.state != 'running')
          )
        "#,
    )
    .execute(&state.pool)
    .await;

    match reconciled {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::warn!(
                "Reconciliation: stopped {} orphaned tracked resources that were already destroyed",
                result.rows_affected()
            );
        }
        Err(e) => {
            tracing::error!("Reconciliation query failed: {}", e);
        }
        _ => {}
    }

    let resources = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut collected = 0;
    let mut orgs_with_deductions = HashSet::new();

    for resource in &resources {
        match collect_resource_usage(state, &resource.resource_id).await {
            Ok(true) => {
                collected += 1;
                orgs_with_deductions.insert(resource.organization_id);
            }
            Ok(false) => {
                collected += 1;
            }
            Err(e) => {
                tracing::error!(
                    "Failed to collect usage for {}: {}",
                    resource.resource_id,
                    e
                );
            }
        }
    }

    // After all resources processed: check balance thresholds per org
    for org_id in orgs_with_deductions {
        if let Err(e) = check_balance_thresholds(state, org_id).await {
            tracing::error!("Failed to check balance thresholds for {}: {}", org_id, e);
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
        SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
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
        organization_id: resource.organization_id,
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
            "application_id": resource.application_id.map(|id| id.to_string()),
            "resource_name": resource.metadata.get("resource_name").cloned(),
        }),
    };

    let pricing = state
        .calculator
        .calculate_pricing(&usage)
        .with_context(|| {
            format!(
                "No pricing configured for resource {} ({})",
                resource.resource_id, resource.provider
            )
        })?;
    let cost = pricing.total_cost_usd;

    // Record usage and advance last_billed_at atomically to prevent double-counting
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO usage_records (
            organization_id, user_id, application_id, resource_id, provider, resource_type,
            quantity, unit, cost_usd, base_unit_cost_usd, margin_percent, unit_cost_usd, recorded_at, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
    )
    .bind(usage.organization_id)
    .bind(usage.user_id)
    .bind(resource.application_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(cost)
    .bind(pricing.base_unit_cost_usd)
    .bind(pricing.margin_percent)
    .bind(pricing.unit_cost_usd)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&mut *tx)
    .await?;

    sqlx::query(r#"UPDATE tracked_resources SET last_billed_at = $1 WHERE resource_id = $2"#)
        .bind(now)
        .bind(resource_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::debug!(
        "Recorded usage for {}: {:.4} hours, ${:.4}",
        resource_id,
        hours,
        cost
    );

    // Real-time credit deduction (wallet_balance keyed by organization_id)
    let cost_cents = (cost * 100.0).round() as i64;
    if cost_cents > 0 {
        let (_applied, _remainder, _new_balance) = crate::credits::deduct_realtime_usage(
            &state.pool,
            resource.organization_id,
            cost_cents,
            resource_id,
            hours,
        )
        .await?;
    }

    // Collect network egress via CloudWatch (best-effort, don't block compute billing)
    if let Err(e) = collect_network_egress(state, &resource, last_billed, now).await {
        tracing::warn!(
            "Failed to collect network egress for {}: {}",
            resource_id,
            e
        );
    }

    Ok(cost_cents > 0)
}

/// Query CloudWatch for NetworkOut bytes and bill for egress.
async fn collect_network_egress(
    state: &AppState,
    resource: &TrackedResource,
    start: time::OffsetDateTime,
    end: time::OffsetDateTime,
) -> Result<()> {
    use aws_sdk_cloudwatch::types::{Dimension, Statistic};

    let cloudwatch_instance_id = resource
        .metadata
        .get("instance_id")
        .and_then(|value| value.as_str())
        .unwrap_or(&resource.resource_id);

    let seconds_elapsed = (end.unix_timestamp() - start.unix_timestamp()).max(60) as i32;

    let result = state
        .cloudwatch
        .get_metric_statistics()
        .namespace("AWS/EC2")
        .metric_name("NetworkOut")
        .dimensions(
            Dimension::builder()
                .name("InstanceId")
                .value(cloudwatch_instance_id)
                .build(),
        )
        .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(
            start.unix_timestamp(),
        ))
        .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(
            end.unix_timestamp(),
        ))
        .period(seconds_elapsed)
        .statistics(Statistic::Sum)
        .send()
        .await
        .context("CloudWatch GetMetricStatistics failed")?;

    let total_bytes: f64 = result.datapoints().iter().filter_map(|dp| dp.sum()).sum();

    if total_bytes < 1.0 {
        return Ok(());
    }

    let gb = total_bytes / (1024.0 * 1024.0 * 1024.0);
    let provider: Provider = resource.provider.parse().unwrap_or(Provider::Aws);

    let usage = ResourceUsage {
        organization_id: resource.organization_id,
        user_id: resource.user_id,
        resource_id: resource.resource_id.clone(),
        provider,
        resource_type: ResourceType::Network,
        quantity: gb,
        unit: UsageUnit::Gb,
        timestamp: end,
        metadata: serde_json::json!({
            "direction": "egress",
            "bytes": total_bytes as i64,
            "instance_id": cloudwatch_instance_id,
            "application_id": resource.application_id.map(|id| id.to_string()),
            "resource_name": resource.metadata.get("resource_name").cloned(),
        }),
    };

    let pricing = state
        .calculator
        .calculate_pricing(&usage)
        .with_context(|| {
            format!(
                "No pricing configured for network egress on resource {} ({})",
                resource.resource_id, resource.provider
            )
        })?;
    let cost = pricing.total_cost_usd;
    let cost_cents = (cost * 100.0).round() as i64;

    if cost_cents <= 0 {
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO usage_records (
            organization_id, user_id, application_id, resource_id, provider, resource_type,
            quantity, unit, cost_usd, base_unit_cost_usd, margin_percent, unit_cost_usd, recorded_at, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
    )
    .bind(usage.organization_id)
    .bind(usage.user_id)
    .bind(resource.application_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(cost)
    .bind(pricing.base_unit_cost_usd)
    .bind(pricing.margin_percent)
    .bind(pricing.unit_cost_usd)
    .bind(end)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await?;

    crate::credits::deduct_realtime_usage(
        &state.pool,
        resource.organization_id,
        cost_cents,
        &resource.resource_id,
        gb,
    )
    .await?;

    tracing::info!(
        "Network egress for {}: {:.4} GB, ${:.4}",
        resource.resource_id,
        gb,
        cost
    );

    Ok(())
}

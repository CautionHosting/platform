// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;

use crate::balance::check_balance_thresholds;
use crate::collection::{
    advisory_unlock, try_advisory_lock, LOCK_MONTHLY_BILLING, LOCK_SUBSCRIPTION_BILLING,
};
use crate::cost_explorer;
use crate::credits::get_ledger_balance_cents;
use crate::AppState;

/// Monthly billing loop.
///
/// Subscription continuity checks run every hour. The AWS month-end catch-up
/// should only run during the first few days of a month because it bills the
/// month that just closed.
pub async fn run_monthly_billing_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;

        if let Err(e) = run_subscription_maintenance(&state).await {
            tracing::error!("Subscription maintenance failed: {}", e);
        }

        let today = time::OffsetDateTime::now_utc().date();
        if today.day() <= 3 {
            tracing::info!("Running monthly billing catch-up for the prior month");

            if let Err(e) = run_monthly_billing_cycle(&state).await {
                tracing::error!("Monthly billing cycle failed: {}", e);
            } else {
                tracing::info!("Monthly billing cycle completed");
            }
        }
    }
}

async fn billing_user_for_org(pool: &PgPool, organization_id: uuid::Uuid) -> Result<uuid::Uuid> {
    sqlx::query_scalar(
        "SELECT user_id
         FROM organization_members
         WHERE organization_id = $1
         ORDER BY joined_at ASC NULLS LAST, user_id ASC
         LIMIT 1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?
    .context("Organization has no members for billing")
}

async fn close_open_subscription_segment(
    tx: &mut Transaction<'_, Postgres>,
    subscription_id: uuid::Uuid,
    period_end: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    sqlx::query(
        "UPDATE subscription_ledger
         SET billing_period_end = $1
         WHERE subscription_id = $2
           AND billing_period_end IS NULL
           AND billing_period_start < $1",
    )
    .bind(period_end)
    .bind(subscription_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Run the monthly billing cycle
async fn run_monthly_billing_cycle(state: &AppState) -> Result<()> {
    if !try_advisory_lock(&state.pool, LOCK_MONTHLY_BILLING).await {
        tracing::debug!("Monthly billing skipped — another instance holds the lock");
        return Ok(());
    }
    let result = run_monthly_billing_cycle_inner(state).await;
    advisory_unlock(&state.pool, LOCK_MONTHLY_BILLING).await;
    result
}

async fn run_monthly_billing_cycle_inner(state: &AppState) -> Result<()> {
    let (start_date, end_date) = cost_explorer::previous_month_billing_period();
    let billing_period = format!("{} to {}", start_date, end_date);

    tracing::info!(
        "Fetching AWS costs for billing period {} to {}",
        start_date,
        end_date
    );

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .context("Failed to create Cost Explorer client")?;

    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .context("Failed to fetch AWS costs")?;

    tracing::info!("Found costs for {} organizations", org_costs.len());

    for (org_id_str, cost_data) in &org_costs {
        let org_id: uuid::Uuid = match org_id_str.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!("Skipping non-UUID org_id: {}", org_id_str);
                continue;
            }
        };

        if cost_data.total_cost < 0.01 {
            tracing::debug!(
                "Skipping org {} with negligible cost: ${:.4}",
                org_id,
                cost_data.total_cost
            );
            continue;
        }

        let monthly_usage_resource_id = format!("monthly-{}-{}", org_id, start_date);
        let already_recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM usage_ledger
                WHERE resource_id = $1
                  AND resource_type = 'monthly_total'
            )",
        )
        .bind(&monthly_usage_resource_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if already_recorded {
            tracing::info!(
                "Skipping org {} for {} — monthly catch-up already recorded",
                org_id,
                billing_period
            );
            continue;
        }

        let total_cost_cents = (cost_data.total_cost * 100.0).round() as i64;
        let realtime_billed_cents: i64 = sqlx::query_scalar(
            "SELECT COALESCE(
                ROUND(
                    SUM(quantity * base_unit_cost_usd * (1 + margin_percent / 100.0)) * 100
                ),
                0
            )::bigint
             FROM usage_ledger
             WHERE organization_id = $1
               AND recorded_at >= $2::date
               AND recorded_at < $3::date
               AND resource_type NOT IN ('monthly_total', 'aws_cost_explorer')
               AND base_unit_cost_usd IS NOT NULL
               AND margin_percent IS NOT NULL",
        )
        .bind(org_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

        let remaining_cost_cents = (total_cost_cents - realtime_billed_cents).max(0);

        if remaining_cost_cents == 0 {
            tracing::info!(
                "Org {} monthly costs (${:.2}) fully covered by real-time metering (${:.2})",
                org_id,
                total_cost_cents as f64 / 100.0,
                realtime_billed_cents as f64 / 100.0
            );

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO usage_ledger (
                    organization_id, user_id, application_id, resource_id, provider, resource_type,
                    quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
                )
                VALUES ($1, $2, NULL, $3, 'aws', 'monthly_total', 0, 'usd', 0, 0, NOW(), $4)
                "#,
            )
            .bind(org_id)
            .bind(billing_user_for_org(&state.pool, org_id).await.ok())
            .bind(&monthly_usage_resource_id)
            .bind(serde_json::json!({
                "source": "aws_cost_explorer",
                "billing_period": {
                    "start": start_date,
                    "end": end_date,
                },
                "services": cost_data.costs_by_service,
                "billing_status": "covered_by_realtime",
                "total_aws_cost_cents": total_cost_cents,
                "realtime_billed_cents": realtime_billed_cents,
                "remaining_cost_cents": 0,
            }))
            .execute(&state.pool)
            .await
            {
                tracing::error!(
                    "Failed to record realtime-covered monthly usage marker for {}: {}",
                    org_id,
                    e
                );
            }

            continue;
        }

        tracing::info!(
            "Org {} monthly: total=${:.2}, real-time metered=${:.2}, remaining to bill=${:.2} (S3/EIP/network)",
            org_id,
            total_cost_cents as f64 / 100.0,
            realtime_billed_cents as f64 / 100.0,
            remaining_cost_cents as f64 / 100.0
        );

        let invoice_user_id = match billing_user_for_org(&state.pool, org_id).await {
            Ok(user_id) => user_id,
            Err(e) => {
                tracing::error!("Org {} has no billable user: {}", org_id, e);
                continue;
            }
        };

        let mut tx = state.pool.begin().await?;
        let balance_cents = get_ledger_balance_cents(&mut *tx, org_id).await?;

        let credits_applied = balance_cents.min(remaining_cost_cents);
        let remainder_cents = remaining_cost_cents - credits_applied;

        if remainder_cents > 0 {
            tracing::info!(
                "Monthly catch-up for org {} is leaving ${:.2} uncollected; direct remainder charging is disabled",
                org_id,
                remainder_cents as f64 / 100.0
            );
        }

        sqlx::query(
            r#"
            INSERT INTO usage_ledger (
                organization_id, user_id, application_id, resource_id, provider, resource_type,
                quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
            )
            VALUES ($1, $2, NULL, $3, 'aws', 'monthly_total', $4, 'usd', 1, 0, NOW(), $5)
            "#,
        )
        .bind(org_id)
        .bind(Some(invoice_user_id))
        .bind(&monthly_usage_resource_id)
        .bind(remaining_cost_cents as f64 / 100.0)
        .bind(serde_json::json!({
            "source": "aws_cost_explorer",
            "billing_period": {
                "start": start_date,
                "end": end_date,
            },
            "services": cost_data.costs_by_service,
            "billing_status": if remainder_cents > 0 {
                "charge_disabled"
            } else {
                "credits_applied"
            },
            "total_aws_cost_cents": total_cost_cents,
            "realtime_billed_cents": realtime_billed_cents,
            "remaining_cost_cents": remaining_cost_cents,
            "credits_applied_cents": credits_applied,
            "charged_amount_cents": 0,
            "uncollected_amount_cents": remainder_cents,
        }))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
    }

    tracing::info!("Monthly billing cycle complete — direct remainder charging is disabled");

    Ok(())
}

/// Check whether subscriptions should remain active.
async fn run_subscription_maintenance(state: &AppState) -> Result<()> {
    if !try_advisory_lock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await {
        tracing::debug!("Subscription maintenance skipped — another instance holds the lock");
        return Ok(());
    }
    let result = run_subscription_maintenance_inner(state).await;
    advisory_unlock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await;
    result
}

async fn run_subscription_maintenance_inner(state: &AppState) -> Result<()> {
    let subs = sqlx::query(
        r#"
        SELECT id, organization_id, status, cancel_at_period_end
        FROM subscriptions
        WHERE status IN ('active', 'past_due')
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    if subs.is_empty() {
        return Ok(());
    }

    tracing::info!("Checking {} active subscriptions", subs.len());

    for row in &subs {
        let sub_id: uuid::Uuid = row.get("id");
        let org_id: uuid::Uuid = row.get("organization_id");
        let status: String = row.get("status");
        let cancel_at_end: bool = row.get("cancel_at_period_end");

        if let Err(e) = check_balance_thresholds(state, org_id).await {
            tracing::error!(
                "Failed to check subscription balance thresholds for {}: {}",
                org_id,
                e
            );
        }

        let balance_cents = get_ledger_balance_cents(&state.pool, org_id).await?;

        if cancel_at_end || balance_cents <= 0 {
            let now = chrono::Utc::now();
            let mut tx = state.pool.begin().await?;
            close_open_subscription_segment(&mut tx, sub_id, now).await?;
            sqlx::query(
                "UPDATE subscriptions SET
                 status = 'canceled',
                 canceled_at = COALESCE(canceled_at, NOW()),
                 cancel_at_period_end = false,
                 current_period_end = $1,
                 next_billing_at = TIMESTAMPTZ '9999-12-31 23:59:59+00',
                 updated_at = NOW()
                 WHERE id = $2",
            )
            .bind(now)
            .bind(sub_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            tracing::info!(
                "Subscription {} canceled ({})",
                sub_id,
                if cancel_at_end {
                    "organization request"
                } else {
                    "insufficient funds"
                }
            );
            continue;
        }

        if status == "past_due" {
            sqlx::query(
                "UPDATE subscriptions SET status = 'active', updated_at = NOW() WHERE id = $1",
            )
            .bind(sub_id)
            .execute(&state.pool)
            .await?;
            tracing::info!("Subscription {} restored to active", sub_id);
        }
    }

    Ok(())
}

/// Manually trigger monthly billing (for testing or catch-up)
pub async fn trigger_monthly_billing(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    tracing::info!("Manually triggering monthly billing cycle");

    match run_monthly_billing_cycle(&state).await {
        Ok(()) => {
            let (start, end) = cost_explorer::previous_month_billing_period();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "success",
                    "message": "Monthly billing cycle completed",
                    "billing_period": {
                        "start": start,
                        "end": end,
                    }
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// =============================================================================
// Billing Estimate (User-facing dashboard)
// =============================================================================

/// Get billing estimate for an org - current spend + projected end-of-month
pub async fn get_billing_estimate(Path(org_id): Path<String>) -> impl IntoResponse {
    let now = time::OffsetDateTime::now_utc();
    let today = now.date();

    // Get current billing period (first of month to today)
    let (start_date, end_date) = cost_explorer::current_billing_period();

    // Calculate days elapsed and remaining
    let first_of_month =
        time::Date::from_calendar_date(today.year(), today.month(), 1).expect("valid date");
    let days_elapsed = (today - first_of_month).whole_days() + 1; // +1 to include today
    let days_in_month = days_in_month(today.year(), today.month());
    let days_remaining = days_in_month - days_elapsed as u8;

    // Fetch current costs from AWS
    let ce_client = match cost_explorer::CostExplorerClient::new().await {
        Ok(client) => client,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to initialize AWS: {}", e)})),
            );
        }
    };

    let cost_data = match ce_client
        .get_org_costs(&org_id, &start_date, &end_date)
        .await
    {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    // Calculate projections
    let current_spend = cost_data.total_cost;
    let daily_average = if days_elapsed > 0 {
        current_spend / days_elapsed as f64
    } else {
        0.0
    };
    let projected_remaining = daily_average * days_remaining as f64;
    let projected_total = current_spend + projected_remaining;

    // Round for display
    let current_spend = (current_spend * 100.0).round() / 100.0;
    let daily_average = (daily_average * 100.0).round() / 100.0;
    let projected_total = (projected_total * 100.0).round() / 100.0;

    // Determine spend trend (compare to previous period if available)
    let spend_trend = if daily_average > 0.0 {
        "active"
    } else {
        "idle"
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "org_id": org_id,
            "billing_period": {
                "start": start_date,
                "end": format!("{}-{:02}-{:02}",
                    today.year(),
                    today.month() as u8,
                    days_in_month
                ),
                "days_elapsed": days_elapsed,
                "days_remaining": days_remaining,
                "days_in_month": days_in_month,
            },
            "current_spend": {
                "amount": current_spend,
                "currency": "USD",
                "as_of": end_date,
            },
            "projection": {
                "daily_average": daily_average,
                "estimated_remaining": (projected_remaining * 100.0).round() / 100.0,
                "estimated_total": projected_total,
                "currency": "USD",
            },
            "breakdown_by_service": cost_data.costs_by_service,
            "trend": spend_trend,
        })),
    )
}

/// Get the number of days in a month
fn days_in_month(year: i32, month: time::Month) -> u8 {
    let next_month = match month {
        time::Month::December => time::Month::January,
        _ => month.next(),
    };
    let next_year = if month == time::Month::December {
        year + 1
    } else {
        year
    };

    let first_of_next =
        time::Date::from_calendar_date(next_year, next_month, 1).expect("valid date");
    let first_of_current = time::Date::from_calendar_date(year, month, 1).expect("valid date");

    (first_of_next - first_of_current).whole_days() as u8
}

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::Row;
use std::sync::Arc;

use crate::collection::{
    advisory_unlock, try_advisory_lock, LOCK_MONTHLY_BILLING, LOCK_SUBSCRIPTION_BILLING,
};
use crate::AppState;
use crate::{cost_explorer, credits, paddle};

/// Monthly billing loop - runs daily, triggers billing on the last day of each month
pub async fn run_monthly_billing_loop(state: Arc<AppState>) {
    // Check once per hour
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;

        // Process subscription renewals on every tick
        if let Err(e) = run_subscription_billing(&state).await {
            tracing::error!("Subscription billing failed: {}", e);
        }

        let now = time::OffsetDateTime::now_utc();
        let today = now.date();
        let current_month = today.month();

        // Check if it's the last day of the month (or first few days of next month as fallback)
        let is_last_day = is_last_day_of_month(today);
        let is_first_of_month = today.day() <= 3; // Fallback: run in first 3 days if we missed month-end

        // Check database for whether we've already billed this month (survives restarts)
        let year_month = format!("{}-{:02}", now.year(), current_month as u8);
        let already_billed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM usage_records WHERE resource_id LIKE 'monthly-%' AND recorded_at >= $1::timestamptz)"
        )
        .bind(format!("{}-01T00:00:00Z", year_month))
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if (is_last_day || (is_first_of_month && !already_billed)) && !already_billed {
            tracing::info!("Running monthly billing cycle for {}", current_month);

            if let Err(e) = run_monthly_billing_cycle(&state).await {
                tracing::error!("Monthly billing cycle failed: {}", e);
            } else {
                tracing::info!("Monthly billing cycle completed for {}", current_month);
            }
        }
    }
}

/// Check if today is the last day of the month
fn is_last_day_of_month(date: time::Date) -> bool {
    let next_day = date + time::Duration::days(1);
    next_day.month() != date.month()
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
    // Get previous month's date range (bill for the month that just ended)
    let (start_date, end_date) = cost_explorer::previous_month_billing_period();

    tracing::info!(
        "Fetching AWS costs for billing period {} to {}",
        start_date,
        end_date
    );

    // Create Cost Explorer client
    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .context("Failed to create Cost Explorer client")?;

    // Get costs for all orgs
    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .context("Failed to fetch AWS costs")?;

    tracing::info!("Found costs for {} organizations", org_costs.len());

    let now = time::OffsetDateTime::now_utc();

    for (org_id_str, cost_data) in &org_costs {
        // Parse org_id as UUID
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

        tracing::info!(
            "Billing org {} for ${:.2} (period: {} to {})",
            org_id,
            cost_data.total_cost,
            start_date,
            end_date
        );

        // Record the monthly usage
        let result = sqlx::query(
            r#"
            INSERT INTO usage_records (organization_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
            VALUES ($1, $2, 'aws', 'monthly_total', $3, 'usd', $3, $4, $5)
            "#,
        )
        .bind(org_id)
        .bind(format!("monthly-{}", start_date))
        .bind(cost_data.total_cost)
        .bind(now)
        .bind(serde_json::json!({
            "source": "aws_cost_explorer",
            "billing_period": {
                "start": start_date,
                "end": end_date,
            },
            "services": cost_data.costs_by_service,
        }))
        .execute(&state.pool)
        .await;

        if let Err(e) = result {
            tracing::error!("Failed to record monthly usage for {}: {}", org_id, e);
            continue;
        }

        let total_cost_cents = (cost_data.total_cost * 100.0).round() as i64;
        let billing_period = format!("{} to {}", start_date, end_date);

        // Subtract costs already billed in real-time (compute + builder) to avoid double-billing.
        // Non-compute costs (S3 storage, EIPs, data transfer) are NOT metered in real-time
        // and must be charged here via the monthly billing cycle.
        let realtime_billed_cents: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM((cost_usd * 100)::bigint), 0) FROM usage_records
             WHERE organization_id = $1
               AND resource_type IN ('compute', 'builder')
               AND recorded_at >= $2::date
               AND recorded_at < $3::date",
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
            continue;
        }

        tracing::info!(
            "Org {} monthly: total=${:.2}, real-time metered=${:.2}, remaining to bill=${:.2} (S3/EIP/network)",
            org_id, total_cost_cents as f64 / 100.0, realtime_billed_cents as f64 / 100.0, remaining_cost_cents as f64 / 100.0
        );

        let total_cost_cents = remaining_cost_cents;

        // Check and deduct prepaid credits before creating Paddle transaction
        let (credits_applied, remainder_cents) = credits::apply_credit_deduction(
            &state.pool,
            org_id,
            total_cost_cents,
            &format!("Monthly billing: {}", billing_period),
            None,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!(
                "Credit deduction failed for {}: {}, falling back to full charge",
                org_id,
                e
            );
            (0, total_cost_cents)
        });

        if credits_applied > 0 {
            tracing::info!(
                "Applied {} cents in credits for org {} (remainder: {} cents)",
                credits_applied,
                org_id,
                remainder_cents
            );
        }

        if remainder_cents == 0 {
            // Fully covered by credits — record a credits-covered invoice, skip Paddle
            let invoice_number = format!("INV-CR-{}-{}", &org_id.to_string()[..8], start_date);
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO invoices (
                    user_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                "#,
            )
            .bind(org_id)
            .bind(&invoice_number)
            .bind(total_cost_cents)
            .execute(&state.pool)
            .await
            {
                tracing::error!(
                    "Failed to insert credits-covered invoice for org {}: {}",
                    org_id,
                    e
                );
            }

            tracing::info!(
                "Org {} billing fully covered by credits (${:.2})",
                org_id,
                total_cost_cents as f64 / 100.0
            );
            continue;
        }

        // Create Paddle transaction for the remainder
        let remainder_cost = remainder_cents as f64 / 100.0;
        let line_items = paddle::PaddleClient::line_items_from_cost_data(
            org_id_str,
            remainder_cost,
            &billing_period,
            &serde_json::json!(cost_data.costs_by_service),
        );

        if line_items.is_empty() {
            tracing::debug!(
                "No billable items for org {}, skipping Paddle transaction",
                org_id
            );
            continue;
        }

        // Look up the org's Paddle customer ID (billing_config is now keyed by organization_id)
        let paddle_customer =
            sqlx::query("SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1")
                .bind(org_id)
                .fetch_optional(&state.pool)
                .await?;

        let paddle_customer_id: Option<String> =
            paddle_customer.and_then(|row| row.get::<Option<String>, _>("paddle_customer_id"));

        if let Some(customer_id) = paddle_customer_id {
            match state
                .paddle
                .create_transaction(&customer_id, line_items)
                .await
            {
                Ok(txn) => {
                    tracing::info!(
                        "Created Paddle transaction {} for org {} (${:.2}, after ${:.2} credits)",
                        txn.id,
                        org_id,
                        remainder_cost,
                        credits_applied as f64 / 100.0
                    );
                    // Record the invoice locally with paddle_transaction_id
                    if let Err(e) = sqlx::query(
                        r#"
                        INSERT INTO invoices (
                            paddle_transaction_id, user_id, invoice_number,
                            amount_cents, currency, status, payment_status,
                            billing_provider, created_at
                        )
                        VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'pending', 'paddle', NOW())
                        "#,
                    )
                    .bind(&txn.id)
                    .bind(org_id)
                    .bind(format!("INV-{}", &txn.id[4..]))
                    .bind(remainder_cents)
                    .execute(&state.pool)
                    .await
                    {
                        tracing::error!(
                            "Failed to insert paddle invoice for org {}: {}",
                            org_id,
                            e
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to create Paddle transaction for org {}: {}",
                        org_id,
                        e
                    );
                }
            }
        } else {
            tracing::warn!("Org {} has no paddle_customer_id, skipping billing", org_id);
        }
    }

    tracing::info!("Monthly billing cycle complete — Paddle will collect payments");

    Ok(())
}

/// Process subscription renewals — called on every hourly tick
async fn run_subscription_billing(state: &AppState) -> Result<()> {
    if !try_advisory_lock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await {
        tracing::debug!("Subscription billing skipped — another instance holds the lock");
        return Ok(());
    }
    let result = run_subscription_billing_inner(state).await;
    advisory_unlock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await;
    result
}

async fn run_subscription_billing_inner(state: &AppState) -> Result<()> {
    let due_subs = sqlx::query(
        r#"
        SELECT id, user_id, organization_id, tier, billing_period,
               price_cents_per_cycle, extra_block_price_cents_per_cycle,
               cancel_at_period_end, status
        FROM subscriptions
        WHERE status IN ('active', 'past_due') AND next_billing_at <= NOW()
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    if due_subs.is_empty() {
        return Ok(());
    }

    tracing::info!("Processing {} due subscription renewals", due_subs.len());

    for row in &due_subs {
        let sub_id: uuid::Uuid = row.get("id");
        let user_id: uuid::Uuid = row.get("user_id");
        let org_id: uuid::Uuid = row.get("organization_id");
        let tier: String = row.get("tier");
        let billing_period: String = row.get("billing_period");
        let base_price: i64 = row.get("price_cents_per_cycle");
        let extra_price: i64 = row.get("extra_block_price_cents_per_cycle");
        let cancel_at_end: bool = row.get("cancel_at_period_end");
        // If flagged for cancellation, cancel now
        if cancel_at_end {
            sqlx::query(
                "UPDATE subscriptions SET status = 'canceled', updated_at = NOW() WHERE id = $1",
            )
            .bind(&sub_id)
            .execute(&state.pool)
            .await?;
            tracing::info!("Subscription {} canceled at period end", sub_id);
            continue;
        }

        let total_charge = base_price + extra_price;
        let now = chrono::Utc::now();
        let period_end = calculate_subscription_period_end(now, &billing_period);

        // Deduct credits first (wallet_balance is keyed by organization_id)
        let (credits_applied, remainder_cents) = credits::apply_credit_deduction(
            &state.pool,
            org_id,
            total_charge,
            &format!("Subscription renewal: {} ({})", tier, billing_period),
            None,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Credit deduction failed for sub {}: {}", sub_id, e);
            (0, total_charge)
        });

        let mut paddle_txn_id: Option<String> = None;
        let mut event_status = if remainder_cents == 0 {
            "credits_covered"
        } else {
            "pending"
        };

        if remainder_cents > 0 {
            // Look up Paddle customer ID (billing_config is keyed by organization_id)
            let paddle_customer_id: Option<String> = sqlx::query(
                "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
            )
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?
            .and_then(|row| row.get::<Option<String>, _>("paddle_customer_id"));

            if let Some(customer_id) = paddle_customer_id {
                let line_items = vec![paddle::LineItem {
                    description: format!("{} subscription renewal ({})", tier, billing_period),
                    quantity: 1,
                    unit_price_amount: remainder_cents.to_string(),
                    unit_price_currency: "USD".to_string(),
                }];

                match state
                    .paddle
                    .create_transaction(&customer_id, line_items)
                    .await
                {
                    Ok(txn) => {
                        tracing::info!(
                            "Created Paddle transaction {} for sub {} renewal (${:.2}, credits ${:.2})",
                            txn.id, sub_id, remainder_cents as f64 / 100.0, credits_applied as f64 / 100.0
                        );
                        paddle_txn_id = Some(txn.id.clone());

                        // Record invoice
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT INTO invoices (
                                paddle_transaction_id, user_id, invoice_number,
                                amount_cents, currency, status, payment_status,
                                billing_provider, created_at
                            )
                            VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'pending', 'paddle', NOW())
                            "#,
                        )
                        .bind(&txn.id)
                        .bind(&org_id)
                        .bind(format!("INV-SUB-{}", &txn.id[4..]))
                        .bind(remainder_cents)
                        .execute(&state.pool)
                        .await
                        {
                            tracing::error!(
                                "Failed to insert sub invoice for sub {}: {}",
                                sub_id,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Paddle charge failed for sub {}: {}", sub_id, e);
                        event_status = "payment_failed";
                        // Mark subscription as past_due
                        if let Err(e) = sqlx::query("UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1")
                            .bind(&sub_id)
                            .execute(&state.pool)
                            .await {
                            tracing::error!("Failed to mark sub {} as past_due: {}", sub_id, e);
                        }
                    }
                }
            } else {
                tracing::warn!("Sub {} org {} has no paddle_customer_id", sub_id, org_id);
                event_status = "payment_failed";
                if let Err(e) = sqlx::query("UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1")
                    .bind(&sub_id)
                    .execute(&state.pool)
                    .await {
                    tracing::error!("Failed to mark sub {} as past_due: {}", sub_id, e);
                }
            }
        } else {
            // Fully credit-covered: record credit-only invoice
            let invoice_number = format!("INV-SUB-CR-{}", &sub_id.to_string()[..8]);
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO invoices (
                    user_id, invoice_number, amount_cents, currency, status, payment_status, billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                "#,
            )
            .bind(&org_id)
            .bind(&invoice_number)
            .bind(total_charge)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to insert credit-covered sub invoice for sub {}: {}", sub_id, e);
            }
        }

        // Record billing event
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO subscription_billing_events
            (subscription_id, user_id, billing_period_start, billing_period_end, tier,
             base_amount_cents, addon_amount_cents, total_amount_cents, credits_applied_cents, charged_amount_cents,
             paddle_transaction_id, status)
            VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&sub_id)
        .bind(&org_id)
        .bind(period_end)
        .bind(&tier)
        .bind(base_price)
        .bind(extra_price)
        .bind(total_charge)
        .bind(credits_applied)
        .bind(remainder_cents)
        .bind(&paddle_txn_id)
        .bind(event_status)
        .execute(&state.pool)
        .await {
            tracing::error!("Failed to record billing event for sub {}: {}", sub_id, e);
        }

        // Advance period (only if charge wasn't a total failure)
        if event_status != "payment_failed" {
            if let Err(e) = sqlx::query(
                "UPDATE subscriptions SET
                 current_period_start = current_period_end,
                 current_period_end = $1,
                 next_billing_at = $1,
                 last_billed_at = NOW(),
                 updated_at = NOW()
                 WHERE id = $2",
            )
            .bind(period_end)
            .bind(&sub_id)
            .execute(&state.pool)
            .await
            {
                tracing::error!("Failed to advance billing period for sub {}: {}", sub_id, e);
            }
        }
    }

    Ok(())
}

pub(crate) fn calculate_subscription_period_end(
    start: chrono::DateTime<chrono::Utc>,
    billing_period: &str,
) -> chrono::DateTime<chrono::Utc> {
    use chrono::{Datelike, NaiveDate};

    let add_months = match billing_period {
        "yearly" => 12,
        "2year" => 24,
        _ => 1,
    };

    let total_months = start.month0() as i32 + add_months;
    let target_year = start.year() + total_months / 12;
    let target_month = (total_months % 12) as u32 + 1;

    // Clamp day to last day of target month to avoid panics (e.g. Jan 31 -> Feb 28)
    let last_day_of_target = NaiveDate::from_ymd_opt(
        target_year,
        if target_month == 12 {
            1
        } else {
            target_month + 1
        },
        1,
    )
    .unwrap_or_else(|| NaiveDate::from_ymd_opt(target_year + 1, 1, 1).unwrap())
    .pred_opt()
    .unwrap()
    .day();

    let day = start.day().min(last_day_of_target);

    start
        .date_naive()
        .with_year(target_year)
        .unwrap_or(start.date_naive())
        .with_month(target_month)
        .unwrap_or(start.date_naive())
        .with_day(day)
        .unwrap_or(start.date_naive())
        .and_time(start.time())
        .and_utc()
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

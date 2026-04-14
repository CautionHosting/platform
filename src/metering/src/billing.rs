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

use crate::collection::{
    advisory_unlock, try_advisory_lock, LOCK_MONTHLY_BILLING, LOCK_SUBSCRIPTION_BILLING,
};
use crate::AppState;
use crate::{cost_explorer, paddle};

/// Monthly billing loop.
///
/// Subscription renewals are processed every hour. The AWS month-end catch-up
/// should only run during the first few days of a month because it bills the
/// month that just closed.
pub async fn run_monthly_billing_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;

        // Process subscription renewals on every tick
        if let Err(e) = run_subscription_billing(&state).await {
            tracing::error!("Subscription billing failed: {}", e);
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

async fn apply_locked_credit_deduction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: uuid::Uuid,
    credits_to_apply: i64,
    description: &str,
    invoice_id: Option<uuid::Uuid>,
) -> Result<i64> {
    if credits_to_apply <= 0 {
        return Ok(0);
    }

    let new_balance: i64 = sqlx::query_scalar(
        "UPDATE wallet_balance
         SET balance_cents = balance_cents - $2, updated_at = NOW()
         WHERE organization_id = $1 AND balance_cents >= $2
         RETURNING balance_cents",
    )
    .bind(organization_id)
    .bind(credits_to_apply)
    .fetch_optional(&mut **tx)
    .await?
    .context("Insufficient locked balance for credit deduction")?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description, invoice_id)
         VALUES ($1, $2, $3, 'billing_deduction', $4, $5)",
    )
    .bind(organization_id)
    .bind(-credits_to_apply)
    .bind(new_balance)
    .bind(description)
    .bind(invoice_id)
    .execute(&mut **tx)
    .await?;

    Ok(new_balance)
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
                FROM usage_records
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
            "SELECT COALESCE(SUM(-delta_cents), 0)
             FROM credit_ledger
             WHERE organization_id = $1
               AND entry_type = 'realtime_usage'
               AND created_at >= $2::date
               AND created_at < $3::date",
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
                INSERT INTO usage_records (
                    organization_id, user_id, application_id, resource_id, provider, resource_type,
                    quantity, unit, cost_usd, base_unit_cost_usd, margin_percent, unit_cost_usd, recorded_at, metadata
                )
                VALUES ($1, $2, NULL, $3, 'aws', 'monthly_total', 0, 'usd', 0, 0, 0, 0, NOW(), $4)
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
        let locked_balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0)
             FROM wallet_balance
             WHERE organization_id = $1
             FOR UPDATE",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(0);

        let credits_applied = locked_balance.min(remaining_cost_cents);
        let remainder_cents = remaining_cost_cents - credits_applied;
        let mut paddle_transaction_id: Option<String> = None;

        let line_items = paddle::PaddleClient::line_items_from_cost_data(
            org_id_str,
            remainder_cents as f64 / 100.0,
            &billing_period,
            &serde_json::json!(cost_data.costs_by_service),
        );

        if remainder_cents > 0 {
            if line_items.is_empty() {
                tracing::warn!(
                    "Monthly catch-up for org {} has {} cents remaining but no billable line items",
                    org_id,
                    remainder_cents
                );
                tx.rollback().await?;
                continue;
            }

            let paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id
                 FROM billing_config
                 WHERE organization_id = $1",
            )
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();

            let Some(customer_id) = paddle_customer_id else {
                tracing::warn!(
                    "Org {} has {} cents due for {} but no paddle_customer_id",
                    org_id,
                    remainder_cents,
                    billing_period
                );
                tx.rollback().await?;
                continue;
            };

            match state.paddle.create_transaction(&customer_id, line_items).await {
                Ok(txn) => {
                    tracing::info!(
                        "Created Paddle transaction {} for org {} (${:.2}, credits ${:.2})",
                        txn.id,
                        org_id,
                        remainder_cents as f64 / 100.0,
                        credits_applied as f64 / 100.0
                    );
                    paddle_transaction_id = Some(txn.id);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to create Paddle transaction for org {} monthly catch-up: {}",
                        org_id,
                        e
                    );
                    tx.rollback().await?;
                    continue;
                }
            }
        }

        let invoice_number = paddle_transaction_id
            .as_ref()
            .map(|txn_id| format!("INV-{}", &txn_id[4..]))
            .unwrap_or_else(|| format!("INV-CR-{}-{}", &org_id.to_string()[..8], start_date));

        let invoice_id: uuid::Uuid = if let Some(txn_id) = paddle_transaction_id.as_ref() {
            sqlx::query_scalar(
                r#"
                INSERT INTO invoices (
                    paddle_transaction_id, user_id, organization_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at
                )
                VALUES ($1, $2, $3, $4, $5, 'USD', 'finalized', 'pending', 'paddle', NOW())
                RETURNING id
                "#,
            )
            .bind(txn_id)
            .bind(invoice_user_id)
            .bind(org_id)
            .bind(&invoice_number)
            .bind(remainder_cents)
            .fetch_one(&mut *tx)
            .await?
        } else {
            sqlx::query_scalar(
                r#"
                INSERT INTO invoices (
                    user_id, organization_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                RETURNING id
                "#,
            )
            .bind(invoice_user_id)
            .bind(org_id)
            .bind(&invoice_number)
            .bind(remaining_cost_cents)
            .fetch_one(&mut *tx)
            .await?
        };

        apply_locked_credit_deduction(
            &mut tx,
            org_id,
            credits_applied,
            &format!("Monthly billing: {}", billing_period),
            Some(invoice_id),
        )
        .await?;

        sqlx::query(
            r#"
            INSERT INTO usage_records (
                organization_id, user_id, application_id, resource_id, provider, resource_type,
                quantity, unit, cost_usd, base_unit_cost_usd, margin_percent, unit_cost_usd, recorded_at, metadata
            )
            VALUES ($1, $2, NULL, $3, 'aws', 'monthly_total', $4, 'usd', $4, 1, 0, 1, NOW(), $5)
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
            "billing_status": if paddle_transaction_id.is_some() {
                "pending_paddle_collection"
            } else {
                "credits_applied"
            },
            "total_aws_cost_cents": total_cost_cents,
            "realtime_billed_cents": realtime_billed_cents,
            "remaining_cost_cents": remaining_cost_cents,
            "credits_applied_cents": credits_applied,
            "charged_amount_cents": remainder_cents,
            "invoice_id": invoice_id,
            "paddle_transaction_id": paddle_transaction_id,
        }))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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
               current_period_start, current_period_end,
               price_cents_per_cycle, extra_block_price_cents_per_cycle,
               cancel_at_period_end
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
        let current_period_start: chrono::DateTime<chrono::Utc> = row.get("current_period_start");
        let current_period_end: chrono::DateTime<chrono::Utc> = row.get("current_period_end");
        let base_price: i64 = row.get("price_cents_per_cycle");
        let extra_price: i64 = row.get("extra_block_price_cents_per_cycle");
        let cancel_at_end: bool = row.get("cancel_at_period_end");

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
        let next_period_end = calculate_subscription_period_end(current_period_end, &billing_period);

        let mut tx = state.pool.begin().await?;
        let locked_balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0)
             FROM wallet_balance
             WHERE organization_id = $1
             FOR UPDATE",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(0);

        let credits_applied = locked_balance.min(total_charge);
        let remainder_cents = total_charge - credits_applied;
        let mut paddle_txn_id: Option<String> = None;

        if remainder_cents > 0 {
            let paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id
                 FROM billing_config
                 WHERE organization_id = $1",
            )
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();

            let Some(customer_id) = paddle_customer_id else {
                tx.rollback().await?;
                sqlx::query(
                    "UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1",
                )
                .bind(sub_id)
                .execute(&state.pool)
                .await?;

                sqlx::query(
                    r#"
                    INSERT INTO subscription_billing_events
                    (subscription_id, user_id, billing_period_start, billing_period_end, tier,
                     base_amount_cents, addon_amount_cents, total_amount_cents, credits_applied_cents,
                     charged_amount_cents, paddle_transaction_id, invoice_id, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, NULL, NULL, 'payment_failed')
                    ON CONFLICT (subscription_id, billing_period_start)
                    DO UPDATE SET status = 'payment_failed'
                    "#,
                )
                .bind(sub_id)
                .bind(user_id)
                .bind(current_period_start)
                .bind(current_period_end)
                .bind(&tier)
                .bind(base_price)
                .bind(extra_price)
                .bind(total_charge)
                .execute(&state.pool)
                .await?;

                tracing::warn!(
                    "Sub {} org {} has no paddle_customer_id; marked past_due",
                    sub_id,
                    org_id
                );
                continue;
            };

            let line_items = vec![paddle::LineItem {
                description: format!("{} subscription renewal ({})", tier, billing_period),
                quantity: 1,
                unit_price_amount: remainder_cents.to_string(),
                unit_price_currency: "USD".to_string(),
            }];

            match state.paddle.create_transaction(&customer_id, line_items).await {
                Ok(txn) => {
                    tracing::info!(
                        "Created Paddle transaction {} for sub {} renewal (${:.2}, credits ${:.2})",
                        txn.id,
                        sub_id,
                        remainder_cents as f64 / 100.0,
                        credits_applied as f64 / 100.0
                    );
                    paddle_txn_id = Some(txn.id);
                }
                Err(e) => {
                    tx.rollback().await?;
                    sqlx::query(
                        "UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1",
                    )
                    .bind(sub_id)
                    .execute(&state.pool)
                    .await?;

                    sqlx::query(
                        r#"
                        INSERT INTO subscription_billing_events
                        (subscription_id, user_id, billing_period_start, billing_period_end, tier,
                         base_amount_cents, addon_amount_cents, total_amount_cents, credits_applied_cents,
                         charged_amount_cents, paddle_transaction_id, invoice_id, status)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, NULL, NULL, 'payment_failed')
                        ON CONFLICT (subscription_id, billing_period_start)
                        DO UPDATE SET status = 'payment_failed'
                        "#,
                    )
                    .bind(sub_id)
                    .bind(user_id)
                    .bind(current_period_start)
                    .bind(current_period_end)
                    .bind(&tier)
                    .bind(base_price)
                    .bind(extra_price)
                    .bind(total_charge)
                    .execute(&state.pool)
                    .await?;

                    tracing::error!("Paddle charge failed for sub {}: {}", sub_id, e);
                    continue;
                }
            }
        }

        let invoice_number = paddle_txn_id
            .as_ref()
            .map(|txn_id| format!("INV-SUB-{}", &txn_id[4..]))
            .unwrap_or_else(|| {
                format!(
                    "INV-SUB-CR-{}-{}",
                    &sub_id.to_string()[..8],
                    current_period_start.format("%Y%m%d%H%M%S")
                )
            });

        let invoice_id: uuid::Uuid = if let Some(txn_id) = paddle_txn_id.as_ref() {
            sqlx::query_scalar(
                r#"
                INSERT INTO invoices (
                    paddle_transaction_id, user_id, organization_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at
                )
                VALUES ($1, $2, $3, $4, $5, 'USD', 'finalized', 'pending', 'paddle', NOW())
                RETURNING id
                "#,
            )
            .bind(txn_id)
            .bind(user_id)
            .bind(org_id)
            .bind(&invoice_number)
            .bind(remainder_cents)
            .fetch_one(&mut *tx)
            .await?
        } else {
            sqlx::query_scalar(
                r#"
                INSERT INTO invoices (
                    user_id, organization_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                RETURNING id
                "#,
            )
            .bind(user_id)
            .bind(org_id)
            .bind(&invoice_number)
            .bind(total_charge)
            .fetch_one(&mut *tx)
            .await?
        };

        apply_locked_credit_deduction(
            &mut tx,
            org_id,
            credits_applied,
            &format!("Subscription renewal: {} ({})", tier, billing_period),
            Some(invoice_id),
        )
        .await?;

        let event_status = if paddle_txn_id.is_some() {
            "pending"
        } else {
            "credits_covered"
        };

        sqlx::query(
            r#"
            INSERT INTO subscription_billing_events
            (subscription_id, user_id, billing_period_start, billing_period_end, tier,
             base_amount_cents, addon_amount_cents, total_amount_cents, credits_applied_cents,
             charged_amount_cents, paddle_transaction_id, invoice_id, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(sub_id)
        .bind(user_id)
        .bind(current_period_start)
        .bind(current_period_end)
        .bind(&tier)
        .bind(base_price)
        .bind(extra_price)
        .bind(total_charge)
        .bind(credits_applied)
        .bind(remainder_cents)
        .bind(&paddle_txn_id)
        .bind(invoice_id)
        .bind(event_status)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE subscriptions SET
             current_period_start = current_period_end,
             current_period_end = $1,
             next_billing_at = $1,
             last_billed_at = NOW(),
             status = 'active',
             updated_at = NOW()
             WHERE id = $2",
        )
        .bind(next_period_end)
        .bind(sub_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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

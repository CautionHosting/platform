// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Prepaid credit deduction for month-end billing and real-time usage.

use sqlx::PgPool;
use uuid::Uuid;

/// Deduct credits from an organization's wallet, returning (credits_applied, remainder).
/// If the org has no credits or insufficient credits, returns partial deduction.
/// Uses SELECT FOR UPDATE to prevent TOCTOU race conditions.
pub async fn apply_credit_deduction(
    pool: &PgPool,
    organization_id: Uuid,
    total_cost_cents: i64,
    description: &str,
    invoice_id: Option<Uuid>,
) -> anyhow::Result<(i64, i64)> {
    let mut tx = pool.begin().await?;

    // Lock the row to prevent concurrent deductions from reading stale balance
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(0);

    if balance_cents <= 0 {
        tx.commit().await?;
        return Ok((0, total_cost_cents));
    }

    let credits_to_apply = balance_cents.min(total_cost_cents);
    let remainder = total_cost_cents - credits_to_apply;

    let new_balance: i64 = sqlx::query_scalar(
        "UPDATE wallet_balance SET balance_cents = balance_cents - $2
         WHERE organization_id = $1
         RETURNING balance_cents",
    )
    .bind(organization_id)
    .bind(credits_to_apply)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description, invoice_id)
         VALUES ($1, $2, $3, 'billing_deduction', $4, $5)"
    )
    .bind(organization_id)
    .bind(-credits_to_apply)
    .bind(new_balance)
    .bind(description)
    .bind(invoice_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        "Credit deduction: org={}, applied={} cents, remainder={} cents, new_balance={}",
        organization_id,
        credits_to_apply,
        remainder,
        new_balance
    );

    Ok((credits_to_apply, remainder))
}

/// Deduct credits in real-time during metering collection cycles.
/// Returns (credits_applied, remainder, new_balance) so the caller can check thresholds.
/// If the org has no credits, returns (0, total_cost_cents, current_balance).
/// Uses SELECT FOR UPDATE to prevent TOCTOU race conditions.
pub async fn deduct_realtime_usage(
    pool: &PgPool,
    organization_id: Uuid,
    cost_cents: i64,
    resource_id: &str,
    hours: f64,
) -> anyhow::Result<(i64, i64, i64)> {
    let mut tx = pool.begin().await?;

    // Lock the row to prevent concurrent deductions
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(0);

    if balance_cents <= 0 {
        tx.commit().await?;
        return Ok((0, cost_cents, balance_cents));
    }

    let credits_to_apply = balance_cents.min(cost_cents);
    let remainder = cost_cents - credits_to_apply;

    let new_balance: i64 = sqlx::query_scalar(
        "UPDATE wallet_balance SET balance_cents = balance_cents - $2
         WHERE organization_id = $1
         RETURNING balance_cents",
    )
    .bind(organization_id)
    .bind(credits_to_apply)
    .fetch_one(&mut *tx)
    .await?;

    let description = format!(
        "Usage: {} ({:.2}h) — {} cents",
        resource_id, hours, credits_to_apply
    );

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description)
         VALUES ($1, $2, $3, 'realtime_usage', $4)"
    )
    .bind(organization_id)
    .bind(-credits_to_apply)
    .bind(new_balance)
    .bind(&description)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        "Realtime deduction: org={}, resource={}, applied={} cents, remainder={}, new_balance={}",
        organization_id,
        resource_id,
        credits_to_apply,
        remainder,
        new_balance
    );

    Ok((credits_to_apply, remainder, new_balance))
}

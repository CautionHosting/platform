// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Prepaid credit deduction for month-end billing and real-time usage.

use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

pub async fn get_ledger_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> anyhow::Result<i64>
where
    E: Executor<'e, Database = Postgres>,
{
    let balance = sqlx::query_scalar(
        r#"
        SELECT COALESCE(clb.credit_cents, 0) - COALESCE(dlb.debit_cents, 0)
        FROM (SELECT $1::uuid AS organization_id) org
        LEFT JOIN credit_ledger_balances clb USING (organization_id)
        LEFT JOIN debit_ledger_balances dlb USING (organization_id)
        "#,
    )
    .bind(organization_id)
    .fetch_one(executor)
    .await?;

    Ok(balance)
}

/// Deduct credits from an organization's wallet, returning (credits_applied, remainder).
/// If the org has no credits or insufficient credits, returns partial deduction.
/// Uses SELECT FOR UPDATE to prevent TOCTOU race conditions.
pub async fn apply_credit_deduction(
    pool: &PgPool,
    organization_id: Uuid,
    total_cost_cents: i64,
    _description: &str,
    _invoice_id: Option<Uuid>,
) -> anyhow::Result<(i64, i64)> {
    let mut tx = pool.begin().await?;

    // Lock the row to prevent concurrent deductions from reading stale balance
    let _locked_wallet_row: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?;

    let balance_cents = get_ledger_balance_cents(&mut *tx, organization_id).await?;

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
    _hours: f64,
) -> anyhow::Result<(i64, i64, i64)> {
    let mut tx = pool.begin().await?;

    // Lock the row to prevent concurrent deductions
    let _locked_wallet_row: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await?;

    let balance_cents = get_ledger_balance_cents(&mut *tx, organization_id).await?;

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

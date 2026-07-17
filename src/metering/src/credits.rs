// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Derived organization balance helpers backed by the ledger views.

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

/// Result of [`credit_ledger_once`].
pub enum CreditOutcome {
    /// A new ledger row was inserted; carries the resulting org balance.
    Credited { new_balance: i64 },
    /// This transaction was already credited (UNIQUE(paddle_transaction_id)
    /// conflict); nothing was changed.
    AlreadyCredited,
}

/// Insert a one-payment-to-one-grant credit for `org_id`, relying on
/// `credit_ledger`'s `UNIQUE(paddle_transaction_id)` constraint for
/// idempotency. A redundant webhook/callback delivery is a no-op
/// ([`CreditOutcome::AlreadyCredited`]); a fresh grant returns the new balance
/// in the same transaction that inserted the row.
pub async fn credit_ledger_once(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Option<Uuid>,
    delta_cents: i64,
    entry_type: &str,
    description: &str,
    paddle_transaction_id: &str,
) -> anyhow::Result<CreditOutcome> {
    let mut tx = pool.begin().await?;

    let inserted = sqlx::query(
        "INSERT INTO credit_ledger (organization_id, user_id, delta_cents, entry_type, description, paddle_transaction_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (paddle_transaction_id) DO NOTHING",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(delta_cents)
    .bind(entry_type)
    .bind(description)
    .bind(paddle_transaction_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 0 {
        tx.rollback().await?;
        return Ok(CreditOutcome::AlreadyCredited);
    }

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id).await?;
    tx.commit().await?;

    Ok(CreditOutcome::Credited { new_balance })
}

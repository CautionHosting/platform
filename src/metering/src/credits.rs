// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Derived organization balance helpers backed by the ledger views.

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetLedgerBalanceError {
    #[error("could not query ledger balance [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreditLedgerOnceError {
    #[error("could not credit ledger [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn get_ledger_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> Result<i64, GetLedgerBalanceError>
where
    E: Executor<'e, Database = Postgres>,
{
    use GetLedgerBalanceErrorCtx as Ctx;

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
    .await
    .with_context(Ctx::database())?;

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
#[tracing::instrument(skip_all, err)]
pub async fn credit_ledger_once(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Option<Uuid>,
    delta_cents: i64,
    entry_type: &str,
    description: &str,
    paddle_transaction_id: &str,
) -> Result<CreditOutcome, CreditLedgerOnceError> {
    use CreditLedgerOnceErrorCtx as Ctx;

    let mut tx = pool.begin().await.with_context(Ctx::database())?;

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
    .await
    .with_context(Ctx::database())?
    .rows_affected();

    if inserted == 0 {
        tx.rollback().await.with_context(Ctx::database())?;
        return Ok(CreditOutcome::AlreadyCredited);
    }

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id)
        .await
        .with_context(Ctx::database())?;
    tx.commit().await.with_context(Ctx::database())?;

    Ok(CreditOutcome::Credited { new_balance })
}

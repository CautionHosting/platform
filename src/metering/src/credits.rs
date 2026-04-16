// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Derived organization balance helpers backed by the ledger views.

use sqlx::{Executor, Postgres};
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

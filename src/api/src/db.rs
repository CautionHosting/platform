// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sqlx::PgPool;
use anyhow::{Context, Result};
use uuid::Uuid;

pub async fn is_user_initialized(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let org_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organization_members WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("Failed to check user initialization")?;
    
    Ok(org_count > 0)
}

pub async fn initialize_user_account(pool: &PgPool, user_id: Uuid) -> Result<Uuid> {
    tracing::info!("Initializing account for user_id: {}", user_id);

    let mut tx = pool.begin().await
        .context("Failed to begin transaction")?;

    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name) VALUES ($1) RETURNING id"
    )
    .bind(format!("Organization for user {}", user_id))
    .fetch_one(&mut *tx)
    .await
    .context("Failed to create organization")?;

    tracing::info!("Created organization {} for user {}", org_id, user_id);
    
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role) 
         VALUES ($1, $2, 'owner')"
    )
    .bind(org_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .context("Failed to add user as organization owner")?;

    let aws_account_id = format!("mvp-test-{}", Uuid::new_v4());
    let role_arn = format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", aws_account_id);

    tracing::info!("Using placeholder AWS account for MVP: {}", aws_account_id);

    sqlx::query(
        "INSERT INTO provider_accounts
         (organization_id, provider_id, external_account_id, account_name, description, role_arn, is_active)
         SELECT $1, id, $2, $3, $4, $5, $6
         FROM providers WHERE provider_type = 'aws'"
    )
    .bind(org_id)
    .bind(&aws_account_id)
    .bind(format!("Org {} AWS Account", org_id))
    .bind("Auto-created AWS provider account (MVP placeholder)")
    .bind(&role_arn)
    .bind(true)
    .execute(&mut *tx)
    .await
    .context("Failed to create provider account")?;

    tracing::info!("Created provider account for org {} with AWS account {}", org_id, aws_account_id);
    
    tx.commit().await
        .context("Failed to commit transaction")?;
    
    tracing::info!("Successfully initialized account for user {}", user_id);
    
    Ok(org_id)
}
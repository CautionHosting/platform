// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sqlx::PgPool;
use anyhow::{Context, Result, bail};
use uuid::Uuid;
use crate::types;

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
         VALUES ($1, $2, $3)"
    )
    .bind(org_id)
    .bind(user_id)
    .bind(types::UserRole::Owner)
    .execute(&mut *tx)
    .await
    .context("Failed to add user as organization owner")?;
    
    // Commit the transaction before Terraform (so org exists even if Terraform fails)
    tx.commit().await
        .context("Failed to commit transaction")?;

    tracing::info!("Database transaction committed for org {}", org_id);

    let root_aws_account_id = std::env::var("AWS_ACCOUNT_ID")
        .unwrap_or_else(|_| "900896541515".to_string());

    tracing::info!("Using root AWS account {} for org {}", root_aws_account_id, org_id);

    create_provider_account(
        pool,
        org_id,
        &root_aws_account_id,
        None,
    ).await
    .context("Failed to create provider account in database")?;
    
    tracing::info!("Successfully initialized account for user {}", user_id);
    
    Ok(org_id)
}

pub fn validate_setup() -> Result<()> {
    if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
        bail!("AWS_ACCESS_KEY_ID environment variable not set");
    }
    if std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
        bail!("AWS_SECRET_ACCESS_KEY environment variable not set");
    }

    Ok(())
}

async fn create_provider_account(
    pool: &PgPool,
    org_id: Uuid,
    aws_account_id: &str,
    role_arn: Option<&str>,
) -> Result<()> {
    let description = if role_arn.is_some() {
        "AWS child account created via Terraform"
    } else {
        "AWS root account (shared)"
    };

    sqlx::query(
        "INSERT INTO provider_accounts
         (organization_id, provider_id, external_account_id, account_name, description, role_arn, is_active)
         SELECT $1, id, $2, $3, $4, $5, true
         FROM providers WHERE provider_type = 'aws'"
    )
    .bind(org_id)
    .bind(aws_account_id)
    .bind(format!("Org {} AWS Account", org_id))
    .bind(description)
    .bind(role_arn)
    .execute(pool)
    .await
    .context("Failed to insert provider account")?;

    tracing::info!("Created provider account for org {} with AWS account {}", org_id, aws_account_id);

    Ok(())
}

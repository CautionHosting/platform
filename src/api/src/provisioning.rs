// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::types;
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::PgPool;
use uuid::Uuid;

const DEFAULT_ORGANIZATION_NAME: &str = "My organization";

/// Failure modes for [`initialize_user_account`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum InitializeUserAccountError {
    #[error("Failed to begin transaction [{location}]")]
    BeginTransaction {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to create organization [{location}]")]
    CreateOrganization {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to add user {user_id} as organization owner of {org_id} [{location}]")]
    AddOwner {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to commit transaction [{location}]")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to create provider account in database [{location}]")]
    CreateProviderAccount {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Creates the default organization and owner membership for a user, then
/// registers the shared root AWS provider account.
#[tracing::instrument(skip_all, err, fields(user_id = %user_id))]
pub async fn initialize_user_account(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Uuid, InitializeUserAccountError> {
    use InitializeUserAccountErrorCtx as Ctx;

    tracing::info!("Initializing account for user_id: {}", user_id);

    let mut tx = pool.begin().await.with_context(Ctx::begin_transaction())?;

    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
            .bind(DEFAULT_ORGANIZATION_NAME)
            .fetch_one(&mut *tx)
            .await
            .with_context(Ctx::create_organization())?;

    tracing::info!("Created organization {} for user {}", org_id, user_id);

    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(types::UserRole::Owner)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::add_owner(org_id, user_id))?;

    // Commit the transaction before Terraform (so org exists even if Terraform fails)
    tx.commit().await.with_context(Ctx::commit())?;

    tracing::info!("Database transaction committed for org {}", org_id);

    let root_aws_account_id =
        std::env::var("AWS_ACCOUNT_ID").unwrap_or_else(|_| "900896541515".to_string());

    tracing::info!(
        "Using root AWS account {} for org {}",
        root_aws_account_id,
        org_id
    );

    create_provider_account(pool, org_id, &root_aws_account_id, None)
        .await
        .with_context(Ctx::create_provider_account())?;

    tracing::info!("Successfully initialized account for user {}", user_id);

    Ok(org_id)
}

/// Failure modes for [`validate_setup`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error)]
pub enum ValidateSetupError {
    #[error("AWS_ACCESS_KEY_ID environment variable not set [{location}]")]
    MissingAccessKeyId { location: Location },

    #[error("AWS_SECRET_ACCESS_KEY environment variable not set [{location}]")]
    MissingSecretAccessKey { location: Location },
}

/// Verifies the AWS credentials required for child-account provisioning are set.
#[tracing::instrument(skip_all, err)]
pub fn validate_setup() -> Result<(), ValidateSetupError> {
    if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
        return Err(ValidateSetupError::MissingAccessKeyId {
            location: std::panic::Location::caller(),
        });
    }
    if std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
        return Err(ValidateSetupError::MissingSecretAccessKey {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

/// Failure modes for [`create_provider_account`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateProviderAccountError {
    #[error(
        "Failed to insert provider account for org {org_id} (AWS account {aws_account_id}) [{location}]"
    )]
    Insert {
        org_id: Uuid,
        #[context(borrow = str)]
        aws_account_id: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn create_provider_account(
    pool: &PgPool,
    org_id: Uuid,
    aws_account_id: &str,
    role_arn: Option<&str>,
) -> Result<(), CreateProviderAccountError> {
    use CreateProviderAccountErrorCtx as Ctx;

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
    .with_context(Ctx::insert(org_id, aws_account_id))?;

    tracing::info!(
        "Created provider account for org {} with AWS account {}",
        org_id,
        aws_account_id
    );

    Ok(())
}

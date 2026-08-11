// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database access layer for reading expected resource state.
//!
//! This module provides functions to query the database and retrieve
//! the expected state of resources that should exist in AWS.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

/// Error types for database access operations.
///
/// Each variant corresponds to a distinct query and carries the identifiers
/// needed to diagnose a failure (organization, resource, etc.).
#[derive(Debug, Error)]
pub enum DbError {
    /// Failed to list active organizations.
    #[error("failed to list active organizations")]
    ListActiveOrganizations(#[source] sqlx::Error),

    /// Failed to list the provider accounts of an organization.
    #[error("failed to list provider accounts for organization {org_id}")]
    ListProviderAccounts {
        /// The organization being queried.
        org_id: Uuid,
        /// The underlying database error.
        #[source]
        source: sqlx::Error,
    },

    /// Failed to list the compute resources of an organization.
    #[error("failed to list compute resources for organization {org_id}")]
    ListComputeResources {
        /// The organization being queried.
        org_id: Uuid,
        /// The underlying database error.
        #[source]
        source: sqlx::Error,
    },

    /// Failed to fetch a single compute resource.
    #[error("failed to fetch compute resource {resource_id} for organization {org_id}")]
    FetchComputeResource {
        /// The organization being queried.
        org_id: Uuid,
        /// The resource being fetched.
        resource_id: Uuid,
        /// The underlying database error.
        #[source]
        source: sqlx::Error,
    },
}

/// Represents a provider account (AWS credentials and configuration).
#[derive(Debug, Clone)]
pub struct ProviderAccount {
    /// The provider account's database ID.
    pub id: Uuid,
    /// The organization this account belongs to.
    pub organization_id: Uuid,
    /// The external (AWS) account ID.
    pub external_account_id: String,
    /// The IAM role ARN used to assume into the account, when configured.
    pub role_arn: Option<String>,
    /// The region to query (e.g. `us-west-2`).
    pub region: String,
}

/// Represents a compute resource expected to exist in AWS.
#[derive(Debug, Clone)]
pub struct ComputeResource {
    /// The resource's database ID.
    pub id: Uuid,
    /// The organization this resource belongs to.
    pub organization_id: Uuid,
    /// The provider account this resource is provisioned in.
    pub provider_account_id: Uuid,
    /// The provider-side resource identifier (e.g. an EC2 instance ID).
    pub provider_resource_id: String,
    /// A human-readable name for the resource, when known.
    pub resource_name: Option<String>,
    /// The expected lifecycle state recorded in the database.
    pub state: ResourceState,
    /// The region the resource is expected to be in.
    pub region: Option<String>,
    /// The expected public IP address, when one is recorded.
    pub public_ip: Option<String>,
    /// Free-form configuration expected for the resource (e.g. `instance_type`).
    pub configuration: Option<serde_json::Value>,
}

/// Represents the lifecycle state of a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceState {
    /// The resource has been created but not yet started.
    Initialized,
    /// The resource is in the process of starting.
    Pending,
    /// The resource is running.
    Running,
    /// The resource is stopped.
    Stopped,
    /// The resource has been terminated.
    Terminated,
    /// The resource is in an unexpected or failed state.
    Failed,
}

impl ResourceState {
    /// Convert to string representation for display.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceState::Initialized => "initialized",
            ResourceState::Pending => "pending",
            ResourceState::Running => "running",
            ResourceState::Stopped => "stopped",
            ResourceState::Terminated => "terminated",
            ResourceState::Failed => "failed",
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for ResourceState {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("resource_state")
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for ResourceState {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let text = value.as_str()?;
        match text {
            "initialized" => Ok(ResourceState::Initialized),
            "pending" => Ok(ResourceState::Pending),
            "running" => Ok(ResourceState::Running),
            "stopped" => Ok(ResourceState::Stopped),
            "terminated" => Ok(ResourceState::Terminated),
            "failed" => Ok(ResourceState::Failed),
            other => Err(format!("Unknown resource state: {other}").into()),
        }
    }
}

impl From<sqlx::postgres::PgRow> for ProviderAccount {
    fn from(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            external_account_id: row.get("external_account_id"),
            role_arn: row.get("role_arn"),
            region: row
                .try_get::<String, _>("region")
                .unwrap_or_else(|_| "us-west-2".to_string()),
        }
    }
}

impl From<sqlx::postgres::PgRow> for ComputeResource {
    fn from(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            provider_account_id: row.get("provider_account_id"),
            provider_resource_id: row.get("provider_resource_id"),
            resource_name: row.get("resource_name"),
            state: row.get("state"),
            region: row.get("region"),
            public_ip: row.get("public_ip"),
            configuration: row.get("configuration"),
        }
    }
}

/// Fetch the IDs of all active organizations, oldest first.
///
/// # Errors
///
/// Returns [`DbError::ListActiveOrganizations`] when the query fails.
pub async fn get_active_organization_ids(pool: &PgPool) -> Result<Vec<Uuid>, DbError> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM organizations WHERE is_active = true ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::ListActiveOrganizations)?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Fetch all active AWS provider accounts for an organization.
///
/// Only active accounts backed by the `aws` provider are returned (drift
/// detection only understands EC2); accounts without a region fall back to
/// `us-west-2`.
///
/// # Errors
///
/// Returns [`DbError::ListProviderAccounts`] when the query fails, carrying
/// the queried organization ID.
pub async fn get_provider_accounts(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ProviderAccount>, DbError> {
    let rows = sqlx::query(
        r"
        SELECT 
            pa.id,
            pa.organization_id,
            pa.external_account_id,
            pa.role_arn,
            COALESCE(pa.region, 'us-west-2') as region
        FROM provider_accounts pa
        JOIN providers p ON p.id = pa.provider_id
        WHERE pa.organization_id = $1 AND pa.is_active = true AND p.provider_type = 'aws'
        ",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|source| DbError::ListProviderAccounts { org_id, source })?;

    let accounts: Vec<ProviderAccount> = rows.into_iter().map(Into::into).collect();

    Ok(accounts)
}

/// Fetch all active compute resources for an organization.
///
/// Only resources that have not been destroyed are returned, newest first.
///
/// # Errors
///
/// Returns [`DbError::ListComputeResources`] when the query fails, carrying
/// the queried organization ID.
pub async fn get_compute_resources(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ComputeResource>, DbError> {
    let rows = sqlx::query(
        r"
        SELECT 
            cr.id,
            cr.organization_id,
            cr.provider_account_id,
            cr.provider_resource_id,
            cr.resource_name,
            cr.state,
            cr.region,
            cr.public_ip,
            cr.configuration
        FROM compute_resources cr
        WHERE cr.organization_id = $1 AND cr.destroyed_at IS NULL
        ORDER BY cr.created_at DESC
        ",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|source| DbError::ListComputeResources { org_id, source })?;

    let resources: Vec<ComputeResource> = rows.into_iter().map(Into::into).collect();

    Ok(resources)
}

/// Fetch a specific compute resource by ID.
///
/// # Errors
///
/// Returns [`DbError::FetchComputeResource`] when the query fails, carrying
/// the queried organization and resource IDs.
pub async fn get_compute_resource(
    pool: &PgPool,
    org_id: Uuid,
    resource_id: Uuid,
) -> Result<Option<ComputeResource>, DbError> {
    let row = sqlx::query(
        r"
        SELECT 
            cr.id,
            cr.organization_id,
            cr.provider_account_id,
            cr.provider_resource_id,
            cr.resource_name,
            cr.state,
            cr.region,
            cr.public_ip,
            cr.configuration
        FROM compute_resources cr
        WHERE cr.id = $1 AND cr.organization_id = $2 AND cr.destroyed_at IS NULL
        ",
    )
    .bind(resource_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_err(|source| DbError::FetchComputeResource {
        org_id,
        resource_id,
        source,
    })?;

    Ok(row.map(Into::into))
}

/// Get the region configured for a provider account.
///
/// Provider accounts always have a region set: decoding falls back to
/// `us-west-2` when the database value is null.
#[must_use]
pub fn get_provider_region(account: &ProviderAccount) -> String {
    account.region.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_state_debug() {
        let state = ResourceState::Running;
        assert_eq!(format!("{:?}", state), "Running");
    }

    #[test]
    fn test_provider_account_debug() {
        let account = ProviderAccount {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            external_account_id: "123456789012".to_string(),
            role_arn: Some("arn:aws:iam::123456789012:role/test".to_string()),
            region: "us-west-2".to_string(),
        };

        let debug_str = format!("{:?}", account);
        assert!(debug_str.contains("external_account_id"));
        assert!(debug_str.contains("123456789012"));
    }

    #[test]
    fn test_db_error_display_includes_context() {
        let err = DbError::ListComputeResources {
            org_id: Uuid::nil(),
            source: sqlx::Error::RowNotFound,
        };
        assert_eq!(
            err.to_string(),
            "failed to list compute resources for organization 00000000-0000-0000-0000-000000000000"
        );

        let err = DbError::FetchComputeResource {
            org_id: Uuid::nil(),
            resource_id: Uuid::nil(),
            source: sqlx::Error::RowNotFound,
        };
        assert!(
            err.to_string()
                .starts_with("failed to fetch compute resource")
        );
    }
}

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::UsageProvider;
use crate::types::{Provider, ResourceType, ResourceUsage, TrackedResource, UsageUnit};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct AwsUsageProvider {
    pool: PgPool,
}

impl AwsUsageProvider {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UsageProvider for AwsUsageProvider {
    fn provider(&self) -> Provider {
        Provider::Aws
    }

    async fn collect_usage(&self) -> Result<Vec<ResourceUsage>> {
        let resources = sqlx::query_as::<_, TrackedResource>(
            r#"
            SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
            FROM tracked_resources
            WHERE provider = 'aws' AND status = 'running'
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let now = time::OffsetDateTime::now_utc();
        let mut usage_records = Vec::new();

        for resource in resources {
            // Calculate hours since last billing using unix timestamps
            let now_unix = now.unix_timestamp();
            let last_billed_unix = resource.last_billed_at.unix_timestamp();
            let seconds_elapsed = (now_unix - last_billed_unix) as f64;
            let hours = seconds_elapsed / 3600.0;

            if hours < 0.01 {
                continue;
            }

            usage_records.push(ResourceUsage {
                organization_id: resource.organization_id,
                user_id: resource.user_id,
                resource_id: resource.resource_id.clone(),
                provider: Provider::Aws,
                resource_type: ResourceType::Compute,
                quantity: hours,
                unit: UsageUnit::Hours,
                timestamp: now,
                metadata: serde_json::json!({
                    "instance_type": resource.instance_type,
                    "region": resource.region,
                    "application_id": resource.application_id.map(|id| id.to_string()),
                }),
            });
        }

        Ok(usage_records)
    }

    async fn get_resource_usage(&self, resource_id: &str) -> Result<Option<ResourceUsage>> {
        let resource = sqlx::query_as::<_, TrackedResource>(
            r#"
            SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
            FROM tracked_resources
            WHERE resource_id = $1 AND provider = 'aws'
            "#,
        )
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(resource) = resource else {
            return Ok(None);
        };

        let now = time::OffsetDateTime::now_utc();
        // Calculate hours since last billing using unix timestamps
        let now_unix = now.unix_timestamp();
        let last_billed_unix = resource.last_billed_at.unix_timestamp();
        let seconds_elapsed = (now_unix - last_billed_unix) as f64;
        let hours = seconds_elapsed / 3600.0;

        Ok(Some(ResourceUsage {
            organization_id: resource.organization_id,
            user_id: resource.user_id,
            resource_id: resource.resource_id,
            provider: Provider::Aws,
            resource_type: ResourceType::Compute,
            quantity: hours,
            unit: UsageUnit::Hours,
            timestamp: now,
            metadata: serde_json::json!({
                "instance_type": resource.instance_type,
                "region": resource.region,
                "application_id": resource.application_id.map(|id| id.to_string()),
            }),
        }))
    }

    async fn track_resource(
        &self,
        resource_id: &str,
        organization_id: Uuid,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let application_id = metadata
            .get("application_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        let tracked_application_id = application_id.clone();
        let instance_type = metadata
            .get("instance_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let region = metadata
            .get("region")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        sqlx::query(
            r#"
            INSERT INTO tracked_resources (resource_id, organization_id, application_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
            VALUES ($1, $2, $3, 'aws', $4, $5, $6, 'running', NOW(), NOW())
            ON CONFLICT (resource_id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                application_id = COALESCE(EXCLUDED.application_id, tracked_resources.application_id),
                status = 'running',
                provider = EXCLUDED.provider,
                instance_type = COALESCE($4, tracked_resources.instance_type),
                region = COALESCE($5, tracked_resources.region),
                metadata = $6,
                started_at = CASE
                    WHEN tracked_resources.status = 'running' THEN tracked_resources.started_at
                    ELSE NOW()
                END,
                stopped_at = NULL,
                last_billed_at = CASE
                    WHEN tracked_resources.status = 'running' THEN tracked_resources.last_billed_at
                    ELSE NOW()
                END
            "#,
        )
        .bind(resource_id)
        .bind(organization_id)
        .bind(application_id)
        .bind(&instance_type)
        .bind(&region)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        tracing::info!("AWS: Now tracking resource: {}", resource_id);
        Ok(())
    }

    async fn untrack_resource(&self, resource_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tracked_resources
            SET status = 'stopped', stopped_at = NOW()
            WHERE resource_id = $1 AND provider = 'aws'
            "#,
        )
        .bind(resource_id)
        .execute(&self.pool)
        .await?;

        tracing::info!("AWS: Stopped tracking resource: {}", resource_id);
        Ok(())
    }
}

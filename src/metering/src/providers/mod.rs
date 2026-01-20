// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod aws;

use crate::types::{Provider, ResourceUsage};
use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

/// Trait for provider-specific usage collection
#[async_trait]
pub trait UsageProvider: Send + Sync {
    /// Get the provider type
    fn provider(&self) -> Provider;

    /// Collect current usage for all tracked resources of this provider
    async fn collect_usage(&self) -> Result<Vec<ResourceUsage>>;

    /// Get usage for a specific resource
    async fn get_resource_usage(&self, resource_id: &str) -> Result<Option<ResourceUsage>>;

    /// Start tracking a new resource
    async fn track_resource(
        &self,
        resource_id: &str,
        user_id: Uuid,
        metadata: serde_json::Value,
    ) -> Result<()>;

    /// Stop tracking a resource
    async fn untrack_resource(&self, resource_id: &str) -> Result<()>;
}

/// Registry of all available usage providers
pub struct ProviderRegistry {
    pub aws: aws::AwsUsageProvider,
    // pub gcp: gcp::GcpUsageProvider,
    // pub azure: azure::AzureUsageProvider,
    // pub baremetal: baremetal::BaremetalUsageProvider,
}

impl ProviderRegistry {
    pub fn new(pool: PgPool) -> Self {
        Self {
            aws: aws::AwsUsageProvider::new(pool.clone()),
        }
    }

    /// Get a provider by type
    pub fn get(&self, provider: Provider) -> Option<&dyn UsageProvider> {
        match provider {
            Provider::Aws => Some(&self.aws),
            _ => None, // Other providers not yet implemented
        }
    }

    /// Get all registered providers
    pub fn all(&self) -> Vec<&dyn UsageProvider> {
        vec![&self.aws]
    }
}

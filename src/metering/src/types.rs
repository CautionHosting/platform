// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct ResourceUsage {
    pub user_id: Uuid,
    pub resource_id: String,
    pub provider: Provider,
    pub resource_type: ResourceType,
    pub quantity: f64,
    pub unit: UsageUnit,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Aws,
    Gcp,
    Azure,
    Baremetal,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Gcp => "gcp",
            Provider::Azure => "azure",
            Provider::Baremetal => "baremetal",
        }
    }
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(Provider::Aws),
            "gcp" => Ok(Provider::Gcp),
            "azure" => Ok(Provider::Azure),
            "baremetal" => Ok(Provider::Baremetal),
            _ => Err(format!("Unknown provider: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Compute,
    Storage,
    Network,
    PublicIp,
    Custom(String),
}

impl ResourceType {
    pub fn as_str(&self) -> &str {
        match self {
            ResourceType::Compute => "compute",
            ResourceType::Storage => "storage",
            ResourceType::Network => "network",
            ResourceType::PublicIp => "public_ip",
            ResourceType::Custom(name) => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageUnit {
    Hours,
    GbHours,
    Gb,
    Count,
    Custom(String),
}

impl UsageUnit {
    pub fn as_str(&self) -> &str {
        match self {
            UsageUnit::Hours => "hours",
            UsageUnit::GbHours => "gb_hours",
            UsageUnit::Gb => "gb",
            UsageUnit::Count => "count",
            UsageUnit::Custom(name) => name,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LagoEvent {
    pub transaction_id: String,
    pub external_customer_id: String,
    pub code: String,
    pub timestamp: i64,
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct TrackedResource {
    pub resource_id: String,
    pub user_id: Uuid,
    pub provider: String,
    pub instance_type: Option<String>,
    pub region: Option<String>,
    pub metadata: serde_json::Value,
    pub status: String,
    pub started_at: time::OffsetDateTime,
    pub stopped_at: Option<time::OffsetDateTime>,
    pub last_billed_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct UsageRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub resource_id: String,
    pub provider: String,
    pub resource_type: String,
    pub quantity: f64,
    pub unit: String,
    pub cost_usd: f64,
    pub recorded_at: time::OffsetDateTime,
    pub metadata: serde_json::Value,
}

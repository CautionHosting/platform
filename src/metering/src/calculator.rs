// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::types::{Provider, ResourceType, ResourceUsage};

pub struct CostCalculator {
    pricing: PricingRules,
}

#[derive(Debug, Clone)]
pub struct PricingRules {
    /// Margin percentage on top of base cloud costs
    pub margin_percent: f64,
    /// Per-provider, per-resource pricing rates
    pub rates: Vec<PricingRate>,
}

#[derive(Debug, Clone)]
pub struct PricingRate {
    pub provider: Provider,
    pub resource_type: ResourceType,
    pub instance_type: Option<String>,
    pub region: Option<String>,
    /// USD per unit (per hour for compute, per GB for storage, etc.)
    pub rate_per_unit: f64,
}

impl Default for PricingRules {
    fn default() -> Self {
        Self {
            margin_percent: 55.0, // 55% margin for verifiable compute
            rates: vec![
                // AWS compute pricing (approximate on-demand rates)
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.192, // ~$0.192/hr
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.2xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.384,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c5.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.17,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c6i.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.17,
                },
                // Default AWS compute rate
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.20, // Default ~$0.20/hr
                },
                // AWS storage
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Storage,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.10 / 720.0, // ~$0.10/GB-month, converted to per-hour
                },
                // AWS network egress
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Network,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.09, // ~$0.09/GB
                },
                // AWS public IP
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::PublicIp,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.005, // ~$0.005/hr for in-use IP
                },
                // GCP defaults
                PricingRate {
                    provider: Provider::Gcp,
                    resource_type: ResourceType::Compute,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.19,
                },
                // Azure defaults
                PricingRate {
                    provider: Provider::Azure,
                    resource_type: ResourceType::Compute,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.19,
                },
                // Baremetal (placeholder - needs real pricing)
                PricingRate {
                    provider: Provider::Baremetal,
                    resource_type: ResourceType::Compute,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.15,
                },
            ],
        }
    }
}

impl PricingRate {
    pub fn matches(&self, usage: &ResourceUsage) -> bool {
        if self.provider != usage.provider {
            return false;
        }
        if self.resource_type != usage.resource_type {
            return false;
        }

        // Check instance type if specified in the rate
        if let Some(ref rate_instance_type) = self.instance_type {
            if let Some(usage_instance_type) = usage.metadata.get("instance_type").and_then(|v| v.as_str()) {
                if rate_instance_type != usage_instance_type {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check region if specified in the rate
        if let Some(ref rate_region) = self.region {
            if let Some(usage_region) = usage.metadata.get("region").and_then(|v| v.as_str()) {
                if rate_region != usage_region {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

impl CostCalculator {
    pub fn new(pricing: PricingRules) -> Self {
        Self { pricing }
    }

    pub fn calculate_cost(&self, usage: &ResourceUsage) -> f64 {
        let base_rate = self.find_rate(usage);
        let base_cost = usage.quantity * base_rate;
        let cost_with_margin = base_cost * (1.0 + self.pricing.margin_percent / 100.0);

        // Round to 6 decimal places
        (cost_with_margin * 1_000_000.0).round() / 1_000_000.0
    }

    fn find_rate(&self, usage: &ResourceUsage) -> f64 {
        // First try to find a specific match (with instance_type/region)
        for rate in &self.pricing.rates {
            if rate.instance_type.is_some() || rate.region.is_some() {
                if rate.matches(usage) {
                    return rate.rate_per_unit;
                }
            }
        }

        // Fall back to a general match (no instance_type/region)
        for rate in &self.pricing.rates {
            if rate.instance_type.is_none() && rate.region.is_none() {
                if rate.matches(usage) {
                    return rate.rate_per_unit;
                }
            }
        }

        // No match found, return 0
        tracing::warn!(
            "No pricing rate found for {:?} {:?}",
            usage.provider,
            usage.resource_type
        );
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UsageUnit;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn test_calculate_cost_with_margin() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = ResourceUsage {
            user_id: Uuid::new_v4(),
            resource_id: "test-resource".to_string(),
            provider: Provider::Aws,
            resource_type: ResourceType::Compute,
            quantity: 10.0, // 10 hours
            unit: UsageUnit::Hours,
            timestamp: OffsetDateTime::now_utc(),
            metadata: serde_json::json!({
                "instance_type": "m5.xlarge",
            }),
        };

        let cost = calculator.calculate_cost(&usage);

        // $0.192/hr * 10 hrs * 1.20 margin = $2.304
        assert!((cost - 2.304).abs() < 0.001);
    }
}

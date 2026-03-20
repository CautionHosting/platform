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
            margin_percent: 75.0, // 75% margin on top of base cloud costs
            rates: vec![
                // AWS compute pricing (on-demand rates, us-west-2)
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.192,
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
                    instance_type: Some("m5.4xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.768,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.8xlarge".to_string()),
                    region: None,
                    rate_per_unit: 1.536,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.12xlarge".to_string()),
                    region: None,
                    rate_per_unit: 2.304,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.16xlarge".to_string()),
                    region: None,
                    rate_per_unit: 3.072,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("m5.24xlarge".to_string()),
                    region: None,
                    rate_per_unit: 4.608,
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
                    instance_type: Some("c5.2xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.34,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c5.4xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.68,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c6i.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.17,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c6i.2xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.34,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c6a.xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.153,
                },
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: Some("c6a.2xlarge".to_string()),
                    region: None,
                    rate_per_unit: 0.306,
                },
                // Default AWS compute rate
                PricingRate {
                    provider: Provider::Aws,
                    resource_type: ResourceType::Compute,
                    instance_type: None,
                    region: None,
                    rate_per_unit: 0.20,
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

    fn make_usage(provider: Provider, resource_type: ResourceType, quantity: f64, metadata: serde_json::Value) -> ResourceUsage {
        ResourceUsage {
            user_id: Uuid::new_v4(),
            resource_id: "test-resource".to_string(),
            provider,
            resource_type,
            quantity,
            unit: UsageUnit::Hours,
            timestamp: OffsetDateTime::now_utc(),
            metadata,
        }
    }

    #[test]
    fn test_calculate_cost_with_margin() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            10.0,
            serde_json::json!({"instance_type": "m5.xlarge"}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.192/hr * 10 hrs * 1.75 margin = $3.36
        assert!((cost - 3.36).abs() < 0.001);
    }

    #[test]
    fn test_fallback_to_default_rate() {
        let calculator = CostCalculator::new(PricingRules::default());

        // Unknown instance type should fall back to default AWS compute rate ($0.20/hr)
        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            10.0,
            serde_json::json!({"instance_type": "r6g.metal"}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.20/hr * 10 hrs * 1.75 = $3.50
        assert!((cost - 3.50).abs() < 0.001);
    }

    #[test]
    fn test_no_instance_type_uses_default() {
        let calculator = CostCalculator::new(PricingRules::default());

        // No instance_type in metadata → default rate
        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            5.0,
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.20/hr * 5 hrs * 1.75 = $1.75
        assert!((cost - 1.75).abs() < 0.001);
    }

    #[test]
    fn test_zero_quantity_returns_zero() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            0.0,
            serde_json::json!({"instance_type": "m5.xlarge"}),
        );

        assert_eq!(calculator.calculate_cost(&usage), 0.0);
    }

    #[test]
    fn test_gcp_compute_default_rate() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Gcp,
            ResourceType::Compute,
            10.0,
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.19/hr * 10 hrs * 1.75 = $3.325
        assert!((cost - 3.325).abs() < 0.001);
    }

    #[test]
    fn test_azure_compute_default_rate() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Azure,
            ResourceType::Compute,
            10.0,
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);
        assert!((cost - 3.325).abs() < 0.001);
    }

    #[test]
    fn test_baremetal_compute_default_rate() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Baremetal,
            ResourceType::Compute,
            10.0,
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.15/hr * 10 hrs * 1.75 = $2.625
        assert!((cost - 2.625).abs() < 0.001);
    }

    #[test]
    fn test_aws_storage_pricing() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Storage,
            720.0, // 720 hours = 1 month
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // ($0.10/720)/hr * 720 hrs * 1.75 = $0.175
        assert!((cost - 0.175).abs() < 0.001);
    }

    #[test]
    fn test_aws_network_pricing() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Network,
            100.0, // 100 GB
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.09/GB * 100 GB * 1.75 = $15.75
        assert!((cost - 15.75).abs() < 0.001);
    }

    #[test]
    fn test_aws_public_ip_pricing() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::PublicIp,
            720.0, // 720 hours
            serde_json::json!({}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.005/hr * 720 hrs * 1.75 = $6.30
        assert!((cost - 6.30).abs() < 0.001);
    }

    #[test]
    fn test_custom_resource_type_returns_zero() {
        let calculator = CostCalculator::new(PricingRules::default());

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Custom("gpu".to_string()),
            10.0,
            serde_json::json!({}),
        );

        // No rate for custom type, returns 0
        assert_eq!(calculator.calculate_cost(&usage), 0.0);
    }

    #[test]
    fn test_specific_instance_type_preferred_over_default() {
        let calculator = CostCalculator::new(PricingRules::default());

        // c5.xlarge has a specific rate of $0.17/hr, default is $0.20/hr
        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            10.0,
            serde_json::json!({"instance_type": "c5.xlarge"}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.17/hr * 10 * 1.75 = $2.975 (NOT $3.50 from default)
        assert!((cost - 2.975).abs() < 0.001);
    }

    #[test]
    fn test_pricing_rate_matches_exact_instance() {
        let rate = PricingRate {
            provider: Provider::Aws,
            resource_type: ResourceType::Compute,
            instance_type: Some("m5.xlarge".to_string()),
            region: None,
            rate_per_unit: 0.192,
        };

        let usage_match = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            1.0,
            serde_json::json!({"instance_type": "m5.xlarge"}),
        );
        assert!(rate.matches(&usage_match));

        let usage_no_match = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            1.0,
            serde_json::json!({"instance_type": "m5.2xlarge"}),
        );
        assert!(!rate.matches(&usage_no_match));
    }

    #[test]
    fn test_pricing_rate_matches_provider() {
        let rate = PricingRate {
            provider: Provider::Aws,
            resource_type: ResourceType::Compute,
            instance_type: None,
            region: None,
            rate_per_unit: 0.20,
        };

        let aws_usage = make_usage(Provider::Aws, ResourceType::Compute, 1.0, serde_json::json!({}));
        assert!(rate.matches(&aws_usage));

        let gcp_usage = make_usage(Provider::Gcp, ResourceType::Compute, 1.0, serde_json::json!({}));
        assert!(!rate.matches(&gcp_usage));
    }

    #[test]
    fn test_custom_margin() {
        let mut rules = PricingRules::default();
        rules.margin_percent = 100.0; // 100% margin = 2x base cost

        let calculator = CostCalculator::new(rules);

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            10.0,
            serde_json::json!({"instance_type": "m5.xlarge"}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.192/hr * 10 hrs * 2.0 = $3.84
        assert!((cost - 3.84).abs() < 0.001);
    }

    #[test]
    fn test_zero_margin() {
        let mut rules = PricingRules::default();
        rules.margin_percent = 0.0;

        let calculator = CostCalculator::new(rules);

        let usage = make_usage(
            Provider::Aws,
            ResourceType::Compute,
            10.0,
            serde_json::json!({"instance_type": "m5.xlarge"}),
        );

        let cost = calculator.calculate_cost(&usage);

        // $0.192/hr * 10 hrs * 1.0 = $1.92
        assert!((cost - 1.92).abs() < 0.001);
    }
}

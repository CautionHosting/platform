// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AWS Cost Explorer integration for fetching real costs by org tag

use anyhow::{Context, Result};
use aws_sdk_costexplorer::{
    types::{
        DateInterval, Expression, Granularity, GroupDefinition, GroupDefinitionType,
        TagValues,
    },
    Client,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tag key used to identify organizations in AWS
const ORG_TAG_KEY: &str = "org_id";

/// AWS Cost Explorer client wrapper
pub struct CostExplorerClient {
    client: Client,
}

/// Cost data for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgCostData {
    pub org_id: String,
    pub start_date: String,
    pub end_date: String,
    pub total_cost: f64,
    pub currency: String,
    pub costs_by_service: HashMap<String, f64>,
}

/// Daily cost breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCost {
    pub date: String,
    pub cost: f64,
    pub currency: String,
}

impl CostExplorerClient {
    /// Create a new Cost Explorer client using default AWS credentials
    pub async fn new() -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Ok(Self { client })
    }

    /// Create with explicit region
    pub async fn with_region(region: &str) -> Result<Self> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        let client = Client::new(&config);
        Ok(Self { client })
    }

    /// Get total costs for an organization within a date range
    pub async fn get_org_costs(
        &self,
        org_id: &str,
        start_date: &str, // YYYY-MM-DD
        end_date: &str,   // YYYY-MM-DD
    ) -> Result<OrgCostData> {
        tracing::info!(
            "Fetching AWS costs for org {} from {} to {}",
            org_id,
            start_date,
            end_date
        );

        // Build filter for this org's tag
        let tag_filter = Expression::builder()
            .tags(
                TagValues::builder()
                    .key(ORG_TAG_KEY)
                    .values(org_id)
                    .build(),
            )
            .build();

        // Query Cost Explorer grouped by service
        let response = self
            .client
            .get_cost_and_usage()
            .time_period(
                DateInterval::builder()
                    .start(start_date)
                    .end(end_date)
                    .build()
                    .context("Failed to build date interval")?,
            )
            .granularity(Granularity::Monthly)
            .filter(tag_filter)
            .group_by(
                GroupDefinition::builder()
                    .r#type(GroupDefinitionType::Dimension)
                    .key("SERVICE")
                    .build(),
            )
            .metrics("UnblendedCost")
            .send()
            .await
            .context("Failed to query AWS Cost Explorer")?;

        let mut total_cost = 0.0;
        let mut costs_by_service = HashMap::new();
        let mut currency = "USD".to_string();

        // Parse results - results_by_time() returns a slice
        for result in response.results_by_time() {
            for group in result.groups() {
                // Get service name
                let service = group
                    .keys()
                    .first()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                // Get cost amount
                if let Some(metrics) = group.metrics() {
                    if let Some(cost_metric) = metrics.get("UnblendedCost") {
                        if let Some(amount_str) = cost_metric.amount() {
                            if let Ok(amount) = amount_str.parse::<f64>() {
                                total_cost += amount;
                                *costs_by_service.entry(service).or_insert(0.0) += amount;
                            }
                        }
                        if let Some(unit) = cost_metric.unit() {
                            currency = unit.to_string();
                        }
                    }
                }
            }
        }

        tracing::info!(
            "Org {} total cost: ${:.2} {} (across {} services)",
            org_id,
            total_cost,
            currency,
            costs_by_service.len()
        );

        Ok(OrgCostData {
            org_id: org_id.to_string(),
            start_date: start_date.to_string(),
            end_date: end_date.to_string(),
            total_cost,
            currency,
            costs_by_service,
        })
    }

    /// Get daily cost breakdown for an organization
    pub async fn get_org_daily_costs(
        &self,
        org_id: &str,
        start_date: &str,
        end_date: &str,
    ) -> Result<Vec<DailyCost>> {
        let tag_filter = Expression::builder()
            .tags(
                TagValues::builder()
                    .key(ORG_TAG_KEY)
                    .values(org_id)
                    .build(),
            )
            .build();

        let response = self
            .client
            .get_cost_and_usage()
            .time_period(
                DateInterval::builder()
                    .start(start_date)
                    .end(end_date)
                    .build()
                    .context("Failed to build date interval")?,
            )
            .granularity(Granularity::Daily)
            .filter(tag_filter)
            .metrics("UnblendedCost")
            .send()
            .await
            .context("Failed to query AWS Cost Explorer")?;

        let mut daily_costs = Vec::new();

        for result in response.results_by_time() {
            let date = result
                .time_period()
                .map(|tp| tp.start().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let mut cost = 0.0;
            let mut currency = "USD".to_string();

            if let Some(total) = result.total() {
                if let Some(cost_metric) = total.get("UnblendedCost") {
                    if let Some(amount_str) = cost_metric.amount() {
                        cost = amount_str.parse().unwrap_or(0.0);
                    }
                    if let Some(unit) = cost_metric.unit() {
                        currency = unit.to_string();
                    }
                }
            }

            daily_costs.push(DailyCost {
                date,
                cost,
                currency,
            });
        }

        Ok(daily_costs)
    }

    /// Get costs for all organizations (returns HashMap of org_id -> cost)
    pub async fn get_all_org_costs(
        &self,
        start_date: &str,
        end_date: &str,
    ) -> Result<HashMap<String, OrgCostData>> {
        tracing::info!(
            "Fetching AWS costs for all orgs from {} to {}",
            start_date,
            end_date
        );

        // Group by org_id tag
        let response = self
            .client
            .get_cost_and_usage()
            .time_period(
                DateInterval::builder()
                    .start(start_date)
                    .end(end_date)
                    .build()
                    .context("Failed to build date interval")?,
            )
            .granularity(Granularity::Monthly)
            .group_by(
                GroupDefinition::builder()
                    .r#type(GroupDefinitionType::Tag)
                    .key(ORG_TAG_KEY)
                    .build(),
            )
            .metrics("UnblendedCost")
            .send()
            .await
            .context("Failed to query AWS Cost Explorer")?;

        let mut org_costs = HashMap::new();

        for result in response.results_by_time() {
            for group in result.groups() {
                // Get org_id from tag
                let org_id = group
                    .keys()
                    .first()
                    .map(|s| {
                        // Tag values come as "org_id$value", extract the value
                        s.split('$').last().unwrap_or(s).to_string()
                    })
                    .unwrap_or_else(|| "untagged".to_string());

                // Skip untagged or empty
                if org_id.is_empty() || org_id == "untagged" {
                    continue;
                }

                // Get cost
                let mut cost = 0.0;
                let mut currency = "USD".to_string();

                if let Some(metrics) = group.metrics() {
                    if let Some(cost_metric) = metrics.get("UnblendedCost") {
                        if let Some(amount_str) = cost_metric.amount() {
                            cost = amount_str.parse().unwrap_or(0.0);
                        }
                        if let Some(unit) = cost_metric.unit() {
                            currency = unit.to_string();
                        }
                    }
                }

                let entry = org_costs.entry(org_id.clone()).or_insert(OrgCostData {
                    org_id: org_id.clone(),
                    start_date: start_date.to_string(),
                    end_date: end_date.to_string(),
                    total_cost: 0.0,
                    currency: currency.clone(),
                    costs_by_service: HashMap::new(),
                });
                entry.total_cost += cost;
            }
        }

        tracing::info!("Found costs for {} orgs", org_costs.len());

        Ok(org_costs)
    }
}

/// Helper to get current billing period dates (first of current month to today)
pub fn current_billing_period() -> (String, String) {
    let now = time::OffsetDateTime::now_utc();
    let start = time::Date::from_calendar_date(now.year(), now.month(), 1)
        .expect("valid date");
    let end = now.date();

    (
        start.to_string(), // YYYY-MM-DD format
        end.to_string(),
    )
}

/// Helper to get previous month's billing period
pub fn previous_month_billing_period() -> (String, String) {
    let now = time::OffsetDateTime::now_utc();
    let first_of_current = time::Date::from_calendar_date(now.year(), now.month(), 1)
        .expect("valid date");

    // Go back one day to get into previous month, then get first of that month
    let last_of_prev = first_of_current - time::Duration::days(1);
    let first_of_prev = time::Date::from_calendar_date(
        last_of_prev.year(),
        last_of_prev.month(),
        1,
    )
    .expect("valid date");

    (
        first_of_prev.to_string(),
        first_of_current.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_billing_period_dates() {
        let (start, end) = current_billing_period();
        assert!(start.starts_with("20")); // Year starts with 20xx
        assert!(end.starts_with("20"));
        assert!(start <= end);
    }
}

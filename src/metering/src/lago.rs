// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use reqwest::Client;

use crate::types::{LagoEvent, ResourceType, ResourceUsage};

pub struct LagoClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl LagoClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
        }
    }

    /// Report usage to Lago as a billable event
    pub async fn report_usage(&self, usage: &ResourceUsage, cost: f64) -> Result<()> {
        if self.api_key.is_empty() {
            tracing::debug!("Lago API key not configured, skipping report");
            return Ok(());
        }

        let event = LagoEvent {
            transaction_id: format!(
                "{}_{}_{}",
                usage.resource_id,
                usage.timestamp.unix_timestamp(),
                uuid::Uuid::new_v4()
            ),
            external_customer_id: usage.user_id.to_string(),
            code: self.metric_code(&usage.resource_type),
            timestamp: usage.timestamp.unix_timestamp(),
            properties: serde_json::json!({
                "provider": usage.provider.as_str(),
                "resource_id": usage.resource_id,
                "quantity": usage.quantity,
                "unit": usage.unit.as_str(),
                "cost_usd": cost,
                "instance_type": usage.metadata.get("instance_type"),
                "region": usage.metadata.get("region"),
            }),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/events", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "event": event }))
            .send()
            .await
            .context("Failed to send event to Lago")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Lago API error: {} - {}", status, body);
        }

        tracing::debug!(
            "Reported usage to Lago: {} ({} {})",
            usage.resource_id,
            usage.quantity,
            usage.unit.as_str()
        );

        Ok(())
    }

    /// Create or update a customer in Lago
    pub async fn upsert_customer(&self, user_id: uuid::Uuid, email: Option<&str>, name: Option<&str>) -> Result<()> {
        if self.api_key.is_empty() {
            return Ok(());
        }

        let customer = serde_json::json!({
            "customer": {
                "external_id": user_id.to_string(),
                "email": email,
                "name": name,
            }
        });

        let response = self
            .client
            .post(format!("{}/api/v1/customers", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&customer)
            .send()
            .await
            .context("Failed to create customer in Lago")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Lago API error: {} - {}", status, body);
        }

        Ok(())
    }

    /// Add credits to a customer's wallet
    pub async fn add_wallet_credits(&self, user_id: uuid::Uuid, amount_cents: i64, currency: &str) -> Result<()> {
        if self.api_key.is_empty() {
            return Ok(());
        }

        // First, get or create wallet
        let wallet_response = self
            .client
            .get(format!("{}/api/v1/wallets", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[("external_customer_id", user_id.to_string())])
            .send()
            .await
            .context("Failed to get wallets from Lago")?;

        if !wallet_response.status().is_success() {
            // Try to create wallet
            let wallet = serde_json::json!({
                "wallet": {
                    "external_customer_id": user_id.to_string(),
                    "name": "Primary Wallet",
                    "rate_amount": "1.0",
                    "currency": currency,
                    "paid_credits": amount_cents.to_string(),
                    "granted_credits": "0",
                }
            });

            let create_response = self
                .client
                .post(format!("{}/api/v1/wallets", self.base_url))
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&wallet)
                .send()
                .await
                .context("Failed to create wallet in Lago")?;

            if !create_response.status().is_success() {
                let status = create_response.status();
                let body = create_response.text().await.unwrap_or_default();
                anyhow::bail!("Lago API error creating wallet: {} - {}", status, body);
            }

            return Ok(());
        }

        // Add credits to existing wallet
        let wallets: serde_json::Value = wallet_response.json().await?;
        if let Some(wallet_id) = wallets["wallets"]
            .as_array()
            .and_then(|w| w.first())
            .and_then(|w| w["lago_id"].as_str())
        {
            let transaction = serde_json::json!({
                "wallet_transaction": {
                    "wallet_id": wallet_id,
                    "paid_credits": amount_cents.to_string(),
                    "granted_credits": "0",
                }
            });

            let tx_response = self
                .client
                .post(format!("{}/api/v1/wallet_transactions", self.base_url))
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&transaction)
                .send()
                .await
                .context("Failed to add credits to wallet")?;

            if !tx_response.status().is_success() {
                let status = tx_response.status();
                let body = tx_response.text().await.unwrap_or_default();
                anyhow::bail!("Lago API error adding credits: {} - {}", status, body);
            }
        }

        Ok(())
    }

    fn metric_code(&self, resource_type: &ResourceType) -> String {
        match resource_type {
            ResourceType::Compute => "compute_hours".to_string(),
            ResourceType::Storage => "storage_gb_hours".to_string(),
            ResourceType::Network => "network_egress_gb".to_string(),
            ResourceType::PublicIp => "public_ip_hours".to_string(),
            ResourceType::Custom(name) => name.clone(),
        }
    }
}

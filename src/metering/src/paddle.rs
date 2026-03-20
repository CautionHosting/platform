// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Paddle Billing API client
//!
//! Replaces Lago for billing. Paddle acts as merchant of record — handling
//! invoicing, payment collection, tax, and compliance. Usage accumulates
//! locally; a single Paddle transaction is created at billing cycle end.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct PaddleClient {
    client: Client,
    base_url: String,
    api_key: String,
    webhook_secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LineItem {
    pub description: String,
    pub quantity: i64,
    pub unit_price_amount: String,
    pub unit_price_currency: String,
}

#[derive(Debug, Deserialize)]
pub struct PaddleCustomer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaddleTransaction {
    pub id: String,
    pub status: String,
    pub customer_id: Option<String>,
}

impl PaddleClient {
    pub fn new(base_url: String, api_key: String, webhook_secret: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
            webhook_secret,
        }
    }

    fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    /// Create a customer in Paddle
    pub async fn create_customer(
        &self,
        org_id: uuid::Uuid,
        email: &str,
        name: Option<&str>,
    ) -> Result<PaddleCustomer> {
        if !self.is_configured() {
            tracing::debug!("Paddle API key not configured, returning stub customer");
            return Ok(PaddleCustomer {
                id: format!("ctm_stub_{}", org_id),
                email: Some(email.to_string()),
                name: name.map(|n| n.to_string()),
            });
        }

        let mut body = serde_json::json!({
            "email": email,
            "custom_data": {
                "org_id": org_id.to_string(),
            }
        });

        if let Some(name) = name {
            body["name"] = serde_json::json!(name);
        }

        let response = self
            .client
            .post(format!("{}/customers", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to create Paddle customer")?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();

            // Handle 409 Conflict — customer already exists with this email
            if status == 409 {
                if let Ok(err_body) = serde_json::from_str::<serde_json::Value>(&body_text) {
                    // Extract existing customer ID from error detail
                    if let Some(detail) = err_body["error"]["detail"].as_str() {
                        if let Some(id_start) = detail.find("ctm_") {
                            let existing_id = &detail[id_start..];
                            tracing::info!("Customer already exists: {}", existing_id);
                            return Ok(PaddleCustomer {
                                id: existing_id.to_string(),
                                email: Some(email.to_string()),
                                name: name.map(|n| n.to_string()),
                            });
                        }
                    }
                }
            }

            anyhow::bail!("Paddle API error creating customer: {} - {}", status, body_text);
        }

        let resp: serde_json::Value = response.json().await?;
        let customer: PaddleCustomer = serde_json::from_value(resp["data"].clone())
            .context("Failed to parse Paddle customer response")?;

        tracing::info!("Created Paddle customer: {}", customer.id);
        Ok(customer)
    }

    /// Create a transaction (one-time charge) for accumulated usage
    pub async fn create_transaction(
        &self,
        customer_id: &str,
        items: Vec<LineItem>,
    ) -> Result<PaddleTransaction> {
        if !self.is_configured() {
            tracing::debug!("Paddle API key not configured, returning stub transaction");
            return Ok(PaddleTransaction {
                id: format!("txn_stub_{}", uuid::Uuid::new_v4()),
                status: "draft".to_string(),
                customer_id: Some(customer_id.to_string()),
            });
        }

        let paddle_items: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "quantity": item.quantity,
                    "price": {
                        "description": item.description,
                        "unit_price": {
                            "amount": item.unit_price_amount,
                            "currency_code": item.unit_price_currency,
                        },
                        "product": {
                            "name": item.description,
                            "tax_category": "standard",
                        }
                    }
                })
            })
            .collect();

        let body = serde_json::json!({
            "customer_id": customer_id,
            "items": paddle_items,
            "collection_mode": "automatic",
        });

        let response = self
            .client
            .post(format!("{}/transactions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to create Paddle transaction")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Paddle API error creating transaction: {} - {}",
                status,
                body
            );
        }

        let resp: serde_json::Value = response.json().await?;
        let transaction: PaddleTransaction = serde_json::from_value(resp["data"].clone())
            .context("Failed to parse Paddle transaction response")?;

        tracing::info!("Created Paddle transaction: {}", transaction.id);
        Ok(transaction)
    }

    /// Get a transaction by ID
    pub async fn get_transaction(&self, transaction_id: &str) -> Result<PaddleTransaction> {
        if !self.is_configured() {
            return Ok(PaddleTransaction {
                id: transaction_id.to_string(),
                status: "completed".to_string(),
                customer_id: None,
            });
        }

        let response = self
            .client
            .get(format!("{}/transactions/{}", self.base_url, transaction_id))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .context("Failed to get Paddle transaction")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Paddle API error getting transaction: {} - {}",
                status,
                body
            );
        }

        let resp: serde_json::Value = response.json().await?;
        let transaction: PaddleTransaction = serde_json::from_value(resp["data"].clone())
            .context("Failed to parse Paddle transaction response")?;

        Ok(transaction)
    }

    /// Verify webhook signature using HMAC-SHA256
    ///
    /// Paddle sends a `Paddle-Signature` header in the format:
    /// `ts=<timestamp>;h1=<hex_signature>`
    pub fn verify_webhook_signature(
        &self,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> Result<bool> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        if self.webhook_secret.is_empty() {
            tracing::warn!("Paddle webhook secret not configured — rejecting webhook");
            anyhow::bail!("PADDLE_WEBHOOK_SECRET not configured, cannot verify webhook");
        }

        let signature_header = headers
            .get("Paddle-Signature")
            .and_then(|v| v.to_str().ok())
            .context("Missing Paddle-Signature header")?;

        // Parse ts=<timestamp>;h1=<signature>
        let mut timestamp = "";
        let mut signature = "";
        for part in signature_header.split(';') {
            if let Some(ts) = part.strip_prefix("ts=") {
                timestamp = ts;
            } else if let Some(h1) = part.strip_prefix("h1=") {
                signature = h1;
            }
        }

        if timestamp.is_empty() || signature.is_empty() {
            anyhow::bail!("Invalid Paddle-Signature format");
        }

        // Compute HMAC-SHA256 of "timestamp:body"
        let signed_payload = format!("{}:{}", timestamp, String::from_utf8_lossy(body));

        let mut mac = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes())
            .context("Invalid webhook secret for HMAC")?;
        mac.update(signed_payload.as_bytes());

        let expected = hex::decode(signature).context("Invalid hex in signature")?;

        Ok(mac.verify_slice(&expected).is_ok())
    }

    /// Convert cost data into Paddle line items
    pub fn line_items_from_cost_data(
        org_id: &str,
        total_cost: f64,
        billing_period: &str,
        _services: &serde_json::Value,
    ) -> Vec<LineItem> {
        // Convert cost to cents as string (Paddle uses minor units)
        let amount_cents = (total_cost * 100.0).round() as i64;

        if amount_cents <= 0 {
            return vec![];
        }

        vec![LineItem {
            description: format!(
                "Caution Platform Usage - {} (org: {})",
                billing_period,
                &org_id[..8.min(org_id.len())]
            ),
            quantity: 1,
            unit_price_amount: amount_cents.to_string(),
            unit_price_currency: "USD".to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_webhook_signature_valid() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "test_webhook_secret";
        let client = PaddleClient::new(
            "https://api.paddle.com".to_string(),
            "".to_string(),
            secret.to_string(),
        );

        let body = b"{\"event_id\":\"evt_123\",\"event_type\":\"transaction.completed\"}";
        let timestamp = "1234567890";

        // Compute the expected signature
        let signed_payload = format!("{}:{}", timestamp, String::from_utf8_lossy(body));
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let sig_hex = hex::encode(mac.finalize().into_bytes());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Paddle-Signature",
            format!("ts={};h1={}", timestamp, sig_hex).parse().unwrap(),
        );

        let result = client.verify_webhook_signature(&headers, body);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_webhook_signature_invalid() {
        let client = PaddleClient::new(
            "https://api.paddle.com".to_string(),
            "".to_string(),
            "test_secret".to_string(),
        );

        let body = b"some body";
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Paddle-Signature",
            "ts=123;h1=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );

        let result = client.verify_webhook_signature(&headers, body);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // signature should not match
    }

    #[test]
    fn test_verify_webhook_signature_missing_header() {
        let client = PaddleClient::new(
            "https://api.paddle.com".to_string(),
            "".to_string(),
            "test_secret".to_string(),
        );

        let headers = axum::http::HeaderMap::new();
        let result = client.verify_webhook_signature(&headers, b"body");
        assert!(result.is_err());
    }

    #[test]
    fn test_line_items_from_cost_data() {
        let items = PaddleClient::line_items_from_cost_data(
            "org-12345678-abcd",
            42.50,
            "2025-01 to 2025-02",
            &serde_json::json!({"EC2": 30.0, "S3": 12.5}),
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].quantity, 1);
        assert_eq!(items[0].unit_price_amount, "4250");
        assert_eq!(items[0].unit_price_currency, "USD");
        assert!(items[0].description.contains("org-1234"));
    }

    #[test]
    fn test_line_items_zero_cost() {
        let items = PaddleClient::line_items_from_cost_data(
            "org-123",
            0.0,
            "2025-01",
            &serde_json::json!({}),
        );
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_client_graceful_when_unconfigured() {
        let client = PaddleClient::new(
            "https://api.paddle.com".to_string(),
            "".to_string(), // empty API key
            "".to_string(),
        );

        // Should return stub data without making HTTP calls
        let customer = client
            .create_customer(
                uuid::Uuid::new_v4(),
                "test@example.com",
                Some("Test"),
            )
            .await;
        assert!(customer.is_ok());
        assert!(customer.unwrap().id.starts_with("ctm_stub_"));

        let transaction = client
            .create_transaction("ctm_123", vec![])
            .await;
        assert!(transaction.is_ok());
        assert!(transaction.unwrap().id.starts_with("txn_stub_"));

        let txn = client.get_transaction("txn_123").await;
        assert!(txn.is_ok());
    }

    /// Helper: load .env and build a PaddleClient from PADDLE_API_URL + PADDLE_API_KEY.
    /// Returns None if Paddle is not configured (tests skip gracefully).
    fn sandbox_client() -> Option<PaddleClient> {
        dotenvy::dotenv().ok();
        let api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
        let api_key = std::env::var("PADDLE_API_KEY").unwrap_or_default();
        if api_key.is_empty() || api_url.is_empty() {
            eprintln!("PADDLE_API_KEY or PADDLE_API_URL not set, skipping sandbox test");
            return None;
        }
        Some(PaddleClient::new(api_url, api_key, "".to_string()))
    }

    #[tokio::test]
    async fn test_create_customer_sandbox() {
        let Some(client) = sandbox_client() else { return };

        let customer = client
            .create_customer(
                uuid::Uuid::new_v4(),
                "sandbox-test@example.com",
                Some("Sandbox Test"),
            )
            .await
            .expect("Should create customer");

        assert!(
            customer.id.starts_with("ctm_"),
            "Customer ID should start with ctm_: {}",
            customer.id
        );
    }

    #[tokio::test]
    async fn test_create_transaction_sandbox() {
        let Some(client) = sandbox_client() else { return };

        let customer = client
            .create_customer(
                uuid::Uuid::new_v4(),
                "sandbox-txn-test@example.com",
                Some("Transaction Test"),
            )
            .await
            .expect("Should create customer");

        let items = vec![LineItem {
            description: "Test compute usage".to_string(),
            quantity: 1,
            unit_price_amount: "1000".to_string(),
            unit_price_currency: "USD".to_string(),
        }];

        let transaction = client
            .create_transaction(&customer.id, items)
            .await
            .expect("Should create transaction");

        assert!(
            transaction.id.starts_with("txn_"),
            "Transaction ID should start with txn_: {}",
            transaction.id
        );
    }

    /// Full lifecycle: create customer → create transaction → retrieve transaction
    #[tokio::test]
    async fn test_full_billing_lifecycle_sandbox() {
        let Some(client) = sandbox_client() else { return };

        // 1. Create customer
        let customer = client
            .create_customer(
                uuid::Uuid::new_v4(),
                "sandbox-lifecycle@example.com",
                Some("Lifecycle Test"),
            )
            .await
            .expect("Should create customer");

        assert!(customer.id.starts_with("ctm_"));

        // 2. Create transaction with multiple line items
        let items = vec![
            LineItem {
                description: "Compute: m5.xlarge (720 hrs)".to_string(),
                quantity: 1,
                unit_price_amount: "24192".to_string(), // $241.92
                unit_price_currency: "USD".to_string(),
            },
            LineItem {
                description: "Network egress (50 GB)".to_string(),
                quantity: 1,
                unit_price_amount: "788".to_string(), // $7.88
                unit_price_currency: "USD".to_string(),
            },
        ];

        let transaction = client
            .create_transaction(&customer.id, items)
            .await
            .expect("Should create transaction");

        assert!(transaction.id.starts_with("txn_"));

        // 3. Retrieve the transaction
        let fetched = client
            .get_transaction(&transaction.id)
            .await
            .expect("Should retrieve transaction");

        assert_eq!(fetched.id, transaction.id);
    }

    /// Verify that creating a customer with the same email returns a 409 or handles gracefully
    #[tokio::test]
    async fn test_duplicate_customer_sandbox() {
        let Some(client) = sandbox_client() else { return };

        let email = format!("sandbox-dup-{}@example.com", uuid::Uuid::new_v4());

        // First creation should succeed
        let customer1 = client
            .create_customer(uuid::Uuid::new_v4(), &email, Some("Dup Test"))
            .await
            .expect("First customer creation should succeed");

        assert!(customer1.id.starts_with("ctm_"));

        // Second creation with same email — Paddle may return 409 or create a new customer
        let result = client
            .create_customer(uuid::Uuid::new_v4(), &email, Some("Dup Test 2"))
            .await;

        // Either succeeds with a new customer or fails gracefully — shouldn't panic
        match result {
            Ok(customer2) => {
                assert!(customer2.id.starts_with("ctm_"));
            }
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("409") || err_msg.contains("conflict") || err_msg.contains("already exists"),
                    "Expected a conflict error, got: {}",
                    err_msg
                );
            }
        }
    }
}

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Webhook handlers for Paddle billing events
//!
//! Paddle acts as merchant of record — it handles payment collection,
//! so we no longer need charge_payment_method() or wallet logic.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;

use crate::AppState;

/// Paddle webhook payload
#[derive(Debug, Deserialize, Serialize)]
pub struct PaddleWebhookPayload {
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub data: serde_json::Value,
}

/// Handle incoming Paddle webhooks
pub async fn paddle_webhook_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Verify webhook signature
    match state.paddle.verify_webhook_signature(&headers, &body) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("Invalid Paddle webhook signature");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid signature"})),
            );
        }
        Err(e) => {
            tracing::warn!("Paddle webhook signature verification error: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "signature verification failed"})),
            );
        }
    }

    // Parse the payload
    let payload: PaddleWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to parse Paddle webhook: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "malformed webhook payload"})),
            );
        }
    };

    tracing::info!(
        "Received Paddle webhook: {} ({})",
        payload.event_type,
        payload.event_id
    );

    // Acquire advisory lock to serialize concurrent processing of same event_id.
    // This prevents two simultaneous deliveries from both passing the INSERT check.
    let lock_key = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        payload.event_id.hash(&mut hasher);
        hasher.finish() as i64
    };

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to begin transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"})));
        }
    };

    if let Err(e) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *tx)
        .await
    {
        tracing::error!("Failed to acquire advisory lock: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"})));
    }

    // Idempotency check (serialized by advisory lock)
    let idempotency_result = sqlx::query(
        r#"
        INSERT INTO paddle_webhook_events (event_id, event_type, payload)
        VALUES ($1, $2, $3)
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(&payload.event_id)
    .bind(&payload.event_type)
    .bind(&payload.data)
    .execute(&mut *tx)
    .await;

    match idempotency_result {
        Ok(result) if result.rows_affected() == 0 => {
            tracing::debug!("Webhook {} already processed, skipping", payload.event_id);
            // tx drops here, releasing the advisory lock
            return (
                StatusCode::OK,
                Json(serde_json::json!({"status": "already_processed"})),
            );
        }
        Err(e) => {
            tracing::error!("Failed to record webhook event for idempotency: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "idempotency check failed"})),
            );
        }
        Ok(_) => {} // rows_affected=1, new event — proceed
    }

    // Commit the idempotency record and release the advisory lock before dispatching.
    // The lock serialization ensures only one handler runs; the committed row prevents retries.
    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit idempotency record: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"})));
    }

    // Dispatch by event type
    let result = match payload.event_type.as_str() {
        "transaction.completed" => handle_transaction_completed(&state, &payload).await,
        "transaction.billed" => handle_transaction_billed(&state, &payload).await,
        "transaction.payment_failed" => handle_payment_failed(&state, &payload).await,
        _ => {
            tracing::debug!("Ignoring Paddle event type: {}", payload.event_type);
            Ok(())
        }
    };

    if let Err(e) = result {
        tracing::error!("Failed to handle Paddle webhook {}: {}", payload.event_type, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "processed"})),
    )
}

/// Handle transaction.completed — payment was collected successfully
async fn handle_transaction_completed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> anyhow::Result<()> {
    let transaction_id = payload.data["id"]
        .as_str()
        .unwrap_or_default();
    let customer_id = payload.data["customer_id"]
        .as_str()
        .unwrap_or_default();

    tracing::info!(
        "Transaction completed: {} for customer {}",
        transaction_id,
        customer_id
    );

    // Find the user by paddle_customer_id
    let user_row = sqlx::query(
        "SELECT user_id FROM billing_config WHERE paddle_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user_row) = user_row else {
        tracing::warn!(
            "No billing_config found for paddle_customer_id: {}",
            customer_id
        );
        return Ok(());
    };

    let user_id: uuid::Uuid = user_row.get("user_id");

    // Update invoice status to paid
    sqlx::query(
        r#"
        UPDATE invoices
        SET payment_status = 'succeeded', paid_at = NOW()
        WHERE paddle_transaction_id = $1
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await?;

    // Also mark any subscription billing event as paid
    if let Err(e) = sqlx::query(
        "UPDATE subscription_billing_events SET status = 'paid' WHERE paddle_transaction_id = $1"
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to mark billing event as paid for txn {}: {}", transaction_id, e);
    }

    // Send confirmation email
    send_payment_confirmation_email(state, user_id, transaction_id).await?;

    // Check if this was an auto top-up transaction — deposit credits and unsuspend if needed
    let line_items = payload.data["details"]["line_items"].as_array();
    let is_auto_topup = line_items
        .map(|items| items.iter().any(|item| {
            item["description"].as_str()
                .map(|d| d.starts_with("Auto top-up"))
                .unwrap_or(false)
        }))
        .unwrap_or(false);

    if is_auto_topup {
        let total_cents = payload.data["details"]["totals"]["total"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        if total_cents <= 0 {
            tracing::error!(
                "Auto top-up transaction {} has invalid total_cents: {}",
                transaction_id, total_cents
            );
            anyhow::bail!("Auto top-up transaction has non-positive amount");
        }

        {
            tracing::info!("Auto top-up completed: depositing {} cents for user {}", total_cents, user_id);

            // Deposit credits to wallet
            let mut tx = state.pool.begin().await?;

            let new_balance: i64 = sqlx::query_scalar(
                "INSERT INTO wallet_balance (user_id, balance_cents)
                 VALUES ($1, $2)
                 ON CONFLICT (user_id) DO UPDATE SET balance_cents = wallet_balance.balance_cents + $2
                 RETURNING balance_cents"
            )
            .bind(user_id)
            .bind(total_cents)
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description, paddle_transaction_id)
                 VALUES ($1, $2, $3, 'auto_topup', $4, $5)"
            )
            .bind(user_id)
            .bind(total_cents)
            .bind(new_balance)
            .bind(format!("Auto top-up: ${:.2}", total_cents as f64 / 100.0))
            .bind(transaction_id)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            tracing::info!("Auto top-up credited: user={}, +{}c, new_balance={}", user_id, total_cents, new_balance);

            // Check if org was credit-suspended and unsuspend
            let org_id: Option<uuid::Uuid> = sqlx::query_scalar(
                "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
            )
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;

            if let Some(org_id) = org_id {
                let suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                    "SELECT credit_suspended_at FROM organizations WHERE id = $1"
                )
                .bind(org_id)
                .fetch_optional(&state.pool)
                .await?
                .flatten();

                if suspended.is_some() {
                    tracing::info!("Clearing credit suspension for org {} after auto top-up", org_id);
                    sqlx::query("UPDATE organizations SET credit_suspended_at = NULL WHERE id = $1")
                        .bind(org_id)
                        .execute(&state.pool)
                        .await?;

                    // Trigger unsuspend
                    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
                    let internal_secret = std::env::var("INTERNAL_SERVICE_SECRET").unwrap_or_default();
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .unwrap_or_else(|_| reqwest::Client::new());
                    let _ = client
                        .post(format!("{}/internal/org/{}/unsuspend", api_url, org_id))
                        .header("x-internal-service-secret", &internal_secret)
                        .header("x-authenticated-user-id", user_id.to_string())
                        .send()
                        .await;
                }
            }
        }
    }

    Ok(())
}

/// Handle transaction.billed — invoice was created/issued
async fn handle_transaction_billed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> anyhow::Result<()> {
    let transaction_id = payload.data["id"]
        .as_str()
        .unwrap_or_default();
    let customer_id = payload.data["customer_id"]
        .as_str()
        .unwrap_or_default();
    let total = payload.data["details"]["totals"]["total"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let tax = payload.data["details"]["totals"]["tax"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let currency = payload.data["currency_code"]
        .as_str()
        .unwrap_or("USD");
    let invoice_number = payload.data["invoice_number"]
        .as_str()
        .unwrap_or("");

    tracing::info!(
        "Transaction billed: {} ({} cents) for customer {}",
        transaction_id,
        total,
        customer_id
    );

    // Find the user
    let user_row = sqlx::query(
        "SELECT user_id FROM billing_config WHERE paddle_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user_row) = user_row else {
        tracing::warn!(
            "No billing_config found for paddle_customer_id: {}",
            customer_id
        );
        return Ok(());
    };

    let user_id: uuid::Uuid = user_row.get("user_id");

    // Record the invoice
    sqlx::query(
        r#"
        INSERT INTO invoices (
            paddle_transaction_id, user_id, invoice_number,
            amount_cents, tax_amount_cents, currency,
            status, payment_status, billing_provider, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'finalized', 'pending', 'paddle', NOW())
        ON CONFLICT (paddle_transaction_id) DO UPDATE SET
            status = 'finalized',
            payment_status = 'pending',
            amount_cents = $4,
            tax_amount_cents = $5
        "#,
    )
    .bind(transaction_id)
    .bind(user_id)
    .bind(invoice_number)
    .bind(total)
    .bind(tax)
    .bind(currency)
    .execute(&state.pool)
    .await?;

    // Send invoice email
    send_invoice_email(state, user_id, transaction_id, total, invoice_number).await?;

    Ok(())
}

/// Handle transaction.payment_failed — payment collection failed
async fn handle_payment_failed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> anyhow::Result<()> {
    let transaction_id = payload.data["id"]
        .as_str()
        .unwrap_or_default();
    let customer_id = payload.data["customer_id"]
        .as_str()
        .unwrap_or_default();

    tracing::warn!(
        "Transaction payment failed: {} for customer {}",
        transaction_id,
        customer_id
    );

    // Find the user
    let user_row = sqlx::query(
        "SELECT user_id FROM billing_config WHERE paddle_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user_row) = user_row else {
        return Ok(());
    };

    let user_id: uuid::Uuid = user_row.get("user_id");

    // Update invoice status
    sqlx::query(
        r#"UPDATE invoices SET payment_status = 'failed' WHERE paddle_transaction_id = $1"#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await?;

    // Mark subscription as past_due if this was a subscription payment
    if let Err(e) = sqlx::query(
        r#"
        UPDATE subscriptions SET status = 'past_due', updated_at = NOW()
        WHERE id IN (
            SELECT subscription_id FROM subscription_billing_events
            WHERE paddle_transaction_id = $1
        )
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to mark subscription as past_due for txn {}: {}", transaction_id, e);
    }

    // Mark the billing event as failed
    if let Err(e) = sqlx::query(
        "UPDATE subscription_billing_events SET status = 'payment_failed' WHERE paddle_transaction_id = $1"
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to mark billing event as payment_failed for txn {}: {}", transaction_id, e);
    }

    send_payment_failure_email(state, user_id, transaction_id).await?;

    Ok(())
}

/// Public entry point for test simulation
pub async fn handle_paddle_transaction_test(
    state: &AppState,
    payload: PaddleWebhookPayload,
) -> anyhow::Result<()> {
    // Record the event for idempotency (same as real webhook handler)
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO paddle_webhook_events (event_id, event_type, payload)
        VALUES ($1, $2, $3)
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(&payload.event_id)
    .bind(&payload.event_type)
    .bind(serde_json::to_value(&payload).unwrap_or_default())
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to record test webhook event {}: {}", payload.event_id, e);
    }

    match payload.event_type.as_str() {
        "transaction.completed" => handle_transaction_completed(state, &payload).await,
        "transaction.billed" => handle_transaction_billed(state, &payload).await,
        "transaction.payment_failed" => handle_payment_failed(state, &payload).await,
        _ => Ok(()),
    }
}

// =============================================================================
// Email helpers (same as before, adapted for Paddle data)
// =============================================================================

async fn send_invoice_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
    amount_cents: i64,
    invoice_number: &str,
) -> anyhow::Result<()> {
    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;

    let Some(user) = user else {
        tracing::warn!("User {} not found for invoice email", user_id);
        return Ok(());
    };

    let email: Option<String> = user.get("email");

    let Some(email) = email else {
        tracing::warn!("User {} has no email address, skipping invoice email", user_id);
        return Ok(());
    };

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    let amount_dollars = amount_cents as f64 / 100.0;

    let email_request = serde_json::json!({
        "to": email,
        "template": "invoice",
        "data": {
            "invoice_number": invoice_number,
            "amount": format!("${:.2}", amount_dollars),
            "currency": "USD",
            "transaction_id": transaction_id,
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let response = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("Invoice email sent to {}", email);
        }
        Ok(resp) => {
            tracing::warn!("Email service returned error: {}", resp.status());
        }
        Err(e) => {
            tracing::warn!("Failed to send invoice email: {}", e);
        }
    }

    Ok(())
}

async fn send_payment_confirmation_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
) -> anyhow::Result<()> {
    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: Option<String> = user.get("email");
    let Some(email) = email else {
        tracing::warn!("User {} has no email, skipping payment confirmation", user_id);
        return Ok(());
    };

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    let email_request = serde_json::json!({
        "to": email,
        "template": "payment_confirmation",
        "data": {
            "transaction_id": transaction_id,
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let _ = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    Ok(())
}

async fn send_payment_failure_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
) -> anyhow::Result<()> {
    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: Option<String> = user.get("email");
    let Some(email) = email else {
        tracing::warn!("User {} has no email, skipping payment failure email", user_id);
        return Ok(());
    };

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    let email_request = serde_json::json!({
        "to": email,
        "template": "payment_failure",
        "data": {
            "transaction_id": transaction_id,
            "update_payment_url": "https://caution.co/billing",
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let _ = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_transaction_completed_webhook() {
        let json = serde_json::json!({
            "event_id": "evt_01h8bkz0d2c8jxqw3f5n0p7m6k",
            "event_type": "transaction.completed",
            "occurred_at": "2025-01-15T10:30:00Z",
            "data": {
                "id": "txn_01h8bkz0d2c8jxqw3f5n0p7m6k",
                "status": "completed",
                "customer_id": "ctm_01h8bkz0d2c8jxqw3f5n0p7m6k",
                "currency_code": "USD",
                "details": {
                    "totals": {
                        "total": "4250",
                        "tax": "0"
                    }
                }
            }
        });

        let payload: PaddleWebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, "transaction.completed");
        assert_eq!(
            payload.data["id"].as_str().unwrap(),
            "txn_01h8bkz0d2c8jxqw3f5n0p7m6k"
        );
    }

    #[test]
    fn test_parse_transaction_billed_webhook() {
        let json = serde_json::json!({
            "event_id": "evt_billed_123",
            "event_type": "transaction.billed",
            "occurred_at": "2025-01-15T10:30:00Z",
            "data": {
                "id": "txn_billed_123",
                "status": "billed",
                "customer_id": "ctm_123",
                "currency_code": "USD",
                "invoice_number": "INV-2025-001",
                "details": {
                    "totals": {
                        "total": "5000",
                        "tax": "500"
                    }
                }
            }
        });

        let payload: PaddleWebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, "transaction.billed");
        assert_eq!(payload.data["invoice_number"].as_str().unwrap(), "INV-2025-001");
    }

    #[test]
    fn test_parse_payment_failed_webhook() {
        let json = serde_json::json!({
            "event_id": "evt_failed_456",
            "event_type": "transaction.payment_failed",
            "occurred_at": "2025-01-15T10:30:00Z",
            "data": {
                "id": "txn_failed_456",
                "status": "past_due",
                "customer_id": "ctm_456"
            }
        });

        let payload: PaddleWebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, "transaction.payment_failed");
    }

    #[test]
    fn test_unknown_event_ignored() {
        let json = serde_json::json!({
            "event_id": "evt_unknown_789",
            "event_type": "subscription.activated",
            "occurred_at": "2025-01-15T10:30:00Z",
            "data": {}
        });

        let payload: PaddleWebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.event_type, "subscription.activated");
        // Should parse without error — unknown events are simply ignored
    }
}

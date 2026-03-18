// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Webhook handlers for Lago billing events

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

/// Lago webhook event types we care about
#[derive(Debug, Deserialize)]
#[serde(tag = "webhook_type")]
#[serde(rename_all = "snake_case")]
pub enum LagoWebhookEvent {
    InvoiceCreated { invoice: Invoice },
    InvoicePaymentStatusUpdated { invoice: Invoice },
    InvoicePaymentFailure { invoice: Invoice },
    WalletTransactionCreated { wallet_transaction: WalletTransaction },
    WalletTransactionUpdated { wallet_transaction: WalletTransaction },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Invoice {
    pub lago_id: String,
    pub sequential_id: i64,
    pub number: String,
    pub issuing_date: String,
    pub status: String,  // draft, finalized, voided
    pub payment_status: String,  // pending, succeeded, failed
    pub currency: String,
    pub total_amount_cents: i64,
    pub taxes_amount_cents: i64,
    pub sub_total_excluding_taxes_amount_cents: i64,
    pub customer: InvoiceCustomer,
    #[serde(default)]
    pub fees: Vec<InvoiceFee>,
    pub file_url: Option<String>,  // PDF URL
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InvoiceCustomer {
    pub lago_id: String,
    pub external_id: String,  // Our user_id
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InvoiceFee {
    pub lago_id: String,
    pub amount_cents: i64,
    pub units: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WalletTransaction {
    pub lago_id: String,
    pub lago_wallet_id: String,
    pub status: String,
    pub transaction_type: String,
    pub amount: String,
    pub credit_amount: String,
}

/// Handle incoming Lago webhooks
pub async fn lago_webhook_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // TODO: Verify webhook signature from X-Lago-Signature header
    let _signature = headers.get("X-Lago-Signature");

    tracing::info!("Received Lago webhook: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());

    // Parse the webhook event
    let event: LagoWebhookEvent = match serde_json::from_value(payload.clone()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Failed to parse Lago webhook: {}", e);
            return (StatusCode::OK, Json(serde_json::json!({"status": "ignored"})));
        }
    };

    match event {
        LagoWebhookEvent::InvoiceCreated { invoice } => {
            if let Err(e) = handle_invoice_created(&state, invoice).await {
                tracing::error!("Failed to handle invoice created: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})));
            }
        }
        LagoWebhookEvent::InvoicePaymentStatusUpdated { invoice } => {
            if let Err(e) = handle_invoice_payment_updated(&state, invoice).await {
                tracing::error!("Failed to handle payment update: {}", e);
            }
        }
        LagoWebhookEvent::InvoicePaymentFailure { invoice } => {
            if let Err(e) = handle_invoice_payment_failure(&state, invoice).await {
                tracing::error!("Failed to handle payment failure: {}", e);
            }
        }
        LagoWebhookEvent::WalletTransactionCreated { wallet_transaction } |
        LagoWebhookEvent::WalletTransactionUpdated { wallet_transaction } => {
            tracing::info!("Wallet transaction: {:?}", wallet_transaction);
        }
        LagoWebhookEvent::Unknown => {
            tracing::debug!("Ignoring unknown webhook type");
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "processed"})))
}

/// Handle new invoice - attempt to charge customer
/// Public alias for testing
pub async fn handle_invoice_created_test(state: &AppState, invoice: Invoice) -> anyhow::Result<()> {
    handle_invoice_created(state, invoice).await
}

async fn handle_invoice_created(state: &AppState, invoice: Invoice) -> anyhow::Result<()> {
    let user_id: uuid::Uuid = invoice.customer.external_id.parse()?;

    tracing::info!(
        "Invoice created for user {}: {} ({} cents)",
        user_id,
        invoice.number,
        invoice.total_amount_cents
    );

    // Get user's billing config
    let billing_config = sqlx::query(
        r#"SELECT billing_mode, payment_method FROM billing_config WHERE user_id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let (billing_mode, payment_method): (String, Option<String>) = billing_config
        .map(|row| {
            (
                row.get::<String, _>("billing_mode"),
                row.get::<Option<String>, _>("payment_method"),
            )
        })
        .unwrap_or(("prepaid".to_string(), None));

    // Record invoice locally
    sqlx::query(
        r#"
        INSERT INTO invoices (lago_invoice_id, user_id, invoice_number, amount_cents, currency, status, payment_status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (lago_invoice_id) DO UPDATE SET
            status = $6,
            payment_status = $7
        "#,
    )
    .bind(&invoice.lago_id)
    .bind(user_id)
    .bind(&invoice.number)
    .bind(invoice.total_amount_cents)
    .bind(&invoice.currency)
    .bind(&invoice.status)
    .bind(&invoice.payment_status)
    .execute(&state.pool)
    .await?;

    // Try to pay the invoice
    match billing_mode.as_str() {
        "prepaid" => {
            // Check wallet balance first
            let balance: i64 = sqlx::query(
                r#"SELECT balance_cents FROM wallet_balance WHERE user_id = $1"#,
            )
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?
            .map(|row| row.get::<i64, _>("balance_cents"))
            .unwrap_or(0);

            if balance >= invoice.total_amount_cents {
                // Deduct from wallet - Lago handles this automatically if configured
                tracing::info!("User {} has sufficient balance, Lago will deduct from wallet", user_id);
            } else {
                // Insufficient balance - try fallback payment method
                tracing::warn!("User {} has insufficient balance ({} < {})", user_id, balance, invoice.total_amount_cents);
                if let Some(ref method) = payment_method {
                    charge_payment_method(state, user_id, &invoice, method).await?;
                } else {
                    // Send email about insufficient balance
                    send_insufficient_balance_email(state, user_id, &invoice).await?;
                }
            }
        }
        "postpaid" => {
            // Charge the payment method directly
            if let Some(ref method) = payment_method {
                charge_payment_method(state, user_id, &invoice, method).await?;
            } else {
                tracing::error!("User {} is postpaid but has no payment method configured", user_id);
            }
        }
        _ => {
            tracing::warn!("Unknown billing mode: {}", billing_mode);
        }
    }

    // Send invoice email
    send_invoice_email(state, user_id, &invoice).await?;

    Ok(())
}

/// Handle invoice payment status update
async fn handle_invoice_payment_updated(state: &AppState, invoice: Invoice) -> anyhow::Result<()> {
    let user_id: uuid::Uuid = invoice.customer.external_id.parse()?;

    tracing::info!(
        "Invoice {} payment status updated: {}",
        invoice.number,
        invoice.payment_status
    );

    // Update local record
    sqlx::query(
        r#"
        UPDATE invoices SET payment_status = $1 WHERE lago_invoice_id = $2
        "#,
    )
    .bind(&invoice.payment_status)
    .bind(&invoice.lago_id)
    .execute(&state.pool)
    .await?;

    if invoice.payment_status == "succeeded" {
        send_payment_confirmation_email(state, user_id, &invoice).await?;
    }

    Ok(())
}

/// Handle invoice payment failure
async fn handle_invoice_payment_failure(state: &AppState, invoice: Invoice) -> anyhow::Result<()> {
    let user_id: uuid::Uuid = invoice.customer.external_id.parse()?;

    tracing::warn!(
        "Invoice {} payment failed for user {}",
        invoice.number,
        user_id
    );

    // Update local record
    sqlx::query(
        r#"
        UPDATE invoices SET payment_status = 'failed' WHERE lago_invoice_id = $1
        "#,
    )
    .bind(&invoice.lago_id)
    .execute(&state.pool)
    .await?;

    // Send payment failure email
    send_payment_failure_email(state, user_id, &invoice).await?;

    Ok(())
}

/// Charge a payment method (PayPal, etc.)
async fn charge_payment_method(
    state: &AppState,
    user_id: uuid::Uuid,
    invoice: &Invoice,
    payment_method: &str,
) -> anyhow::Result<()> {
    tracing::info!(
        "Charging user {} via {} for invoice {}",
        user_id,
        payment_method,
        invoice.number
    );

    // Record the payment attempt
    let result = sqlx::query(
        r#"
        INSERT INTO payment_transactions (user_id, amount_cents, currency, payment_method, transaction_type, status, metadata)
        VALUES ($1, $2, $3, $4, 'invoice_payment', 'pending', $5)
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(invoice.total_amount_cents)
    .bind(&invoice.currency)
    .bind(payment_method)
    .bind(serde_json::json!({
        "invoice_number": invoice.number,
        "lago_invoice_id": invoice.lago_id,
    }))
    .fetch_one(&state.pool)
    .await?;

    let transaction_id: uuid::Uuid = result.get("id");

    match payment_method {
        "paypal" => {
            // TODO: Implement PayPal charge
            // 1. Get user's PayPal billing agreement ID from storage
            // 2. Call PayPal Billing Agreements API to charge
            // 3. Update transaction status based on result
            tracing::info!("PayPal payment would be processed here for transaction {}", transaction_id);
        }
        "crypto" => {
            // TODO: Implement crypto payment request
            // 1. Generate payment address/invoice
            // 2. Send payment request to user
            // 3. Monitor for payment (separate process)
            tracing::info!("Crypto payment would be requested here for transaction {}", transaction_id);
        }
        "card" => {
            // TODO: Implement card charge via PayPal or Stripe
            tracing::info!("Card payment would be processed here for transaction {}", transaction_id);
        }
        _ => {
            tracing::warn!("Unknown payment method: {}", payment_method);
        }
    }

    Ok(())
}

/// Send invoice email to user
async fn send_invoice_email(state: &AppState, user_id: uuid::Uuid, invoice: &Invoice) -> anyhow::Result<()> {
    // Get user email
    let user = sqlx::query(
        r#"SELECT email FROM users WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = user else {
        tracing::warn!("User {} not found for invoice email", user_id);
        return Ok(());
    };

    let email: String = user.get("email");

    let email_service_url = std::env::var("EMAIL_SERVICE_URL")
        .unwrap_or_else(|_| "http://email:8082".to_string());

    let amount_dollars = invoice.total_amount_cents as f64 / 100.0;

    let email_request = serde_json::json!({
        "to": email,
        "template": "invoice",
        "data": {
            "invoice_number": invoice.number,
            "amount": format!("${:.2}", amount_dollars),
            "currency": invoice.currency,
            "date": invoice.issuing_date,
            "pdf_url": invoice.file_url,
        }
    });

    let client = reqwest::Client::new();
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

async fn send_payment_confirmation_email(state: &AppState, user_id: uuid::Uuid, invoice: &Invoice) -> anyhow::Result<()> {
    let user = sqlx::query(
        r#"SELECT email FROM users WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: String = user.get("email");

    let email_service_url = std::env::var("EMAIL_SERVICE_URL")
        .unwrap_or_else(|_| "http://email:8082".to_string());

    let amount_dollars = invoice.total_amount_cents as f64 / 100.0;

    let email_request = serde_json::json!({
        "to": email,
        "template": "payment_confirmation",
        "data": {
            "invoice_number": invoice.number,
            "amount": format!("${:.2}", amount_dollars),
        }
    });

    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    Ok(())
}

async fn send_payment_failure_email(state: &AppState, user_id: uuid::Uuid, invoice: &Invoice) -> anyhow::Result<()> {
    let user = sqlx::query(
        r#"SELECT email FROM users WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: String = user.get("email");

    let email_service_url = std::env::var("EMAIL_SERVICE_URL")
        .unwrap_or_else(|_| "http://email:8082".to_string());

    let amount_dollars = invoice.total_amount_cents as f64 / 100.0;

    let email_request = serde_json::json!({
        "to": email,
        "template": "payment_failure",
        "data": {
            "invoice_number": invoice.number,
            "amount": format!("${:.2}", amount_dollars),
        }
    });

    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    Ok(())
}

async fn send_insufficient_balance_email(state: &AppState, user_id: uuid::Uuid, invoice: &Invoice) -> anyhow::Result<()> {
    let user = sqlx::query(
        r#"SELECT email FROM users WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: String = user.get("email");

    let email_service_url = std::env::var("EMAIL_SERVICE_URL")
        .unwrap_or_else(|_| "http://email:8082".to_string());

    let amount_dollars = invoice.total_amount_cents as f64 / 100.0;

    let email_request = serde_json::json!({
        "to": email,
        "template": "insufficient_balance",
        "data": {
            "invoice_number": invoice.number,
            "amount": format!("${:.2}", amount_dollars),
            "topup_url": "https://caution.co/billing/topup",
        }
    });

    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await;

    Ok(())
}

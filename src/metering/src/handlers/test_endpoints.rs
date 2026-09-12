// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use std::sync::Arc;

use crate::types::*;
use crate::AppState;

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TestSimulateUsageError {
    #[error("no pricing configured for resource type '{resource_type}' [{location}]")]
    NoPricing {
        resource_type: String,
        location: Location,
    },
    #[error("could not record simulated usage [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TestSimulateUsageError {
    fn into_response(self) -> Response {
        let err = &self;
        match self {
            Self::NoPricing { .. } => {
                tracing::error!(?err, "test simulate usage: no pricing");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "no pricing configured for this resource type"})),
                )
                    .into_response()
            }
            Self::Database { .. } => {
                tracing::error!(?err, "test simulate usage: database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TestSimulatePaddleTransactionError {
    #[error("could not process paddle transaction [{location}]")]
    Webhook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TestSimulatePaddleTransactionError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "test simulate paddle transaction error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct TestSimulateUsageRequest {
    user_id: uuid::Uuid,
    organization_id: Option<uuid::Uuid>,
    application_id: Option<uuid::Uuid>,
    hours: Option<f64>,
    instance_type: Option<String>,
}

/// Simulate resource usage for testing the billing pipeline
#[tracing::instrument(skip_all, err)]
pub(crate) async fn test_simulate_usage(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulateUsageRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TestSimulateUsageError> {
    use TestSimulateUsageErrorCtx as Ctx;

    let hours = req.hours.unwrap_or(1.0);
    let instance_type = req.instance_type.unwrap_or_else(|| "m5.xlarge".to_string());
    let resource_id = format!("test-{}", uuid::Uuid::new_v4());

    let now = time::OffsetDateTime::now_utc();

    let usage = ResourceUsage {
        organization_id: req.organization_id.unwrap_or(req.user_id),
        user_id: Some(req.user_id),
        resource_id: resource_id.clone(),
        provider: Provider::Aws,
        resource_type: ResourceType::Compute,
        quantity: hours,
        unit: UsageUnit::Hours,
        timestamp: now,
        metadata: serde_json::json!({
            "instance_type": instance_type,
            "region": "us-west-2",
        }),
    };

    let Some(pricing) = state.calculator.calculate_pricing(&usage) else {
        return Err(TestSimulateUsageError::NoPricing {
            resource_type: usage.resource_type.as_str().to_string(),
            location: std::panic::Location::caller(),
        });
    };
    let cost = pricing.total_cost_usd(usage.quantity);

    sqlx::query(
        r#"
        INSERT INTO usage_ledger (
            organization_id, user_id, application_id, resource_id, provider, resource_type,
            quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(usage.organization_id)
    .bind(usage.user_id)
    .bind(req.application_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(pricing.base_unit_cost_usd)
    .bind(pricing.margin_percent)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!(
        "TEST: Simulated {} hours of {} usage for user {}, cost: ${:.4}",
        hours,
        instance_type,
        req.user_id,
        cost
    );

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "resource_id": resource_id,
            "hours": hours,
            "instance_type": instance_type,
            "cost_usd": cost,
            "message": "Usage recorded locally. Paddle transaction will be created at billing cycle end."
        })),
    ))
}

#[derive(serde::Deserialize)]
pub(crate) struct TestSimulatePaddleTransactionRequest {
    user_id: uuid::Uuid,
    #[serde(default)]
    organization_id: Option<uuid::Uuid>,
    amount_cents: i64,
    #[serde(default)]
    event_type: Option<String>, // transaction.completed, transaction.billed, transaction.payment_failed
    #[serde(default)]
    transaction_id: Option<String>, // reuse a specific transaction ID (e.g. from a prior billed event)
    #[serde(default)]
    custom_data: Option<serde_json::Value>, // optional transaction custom_data (e.g. to exercise credit-purchase paths)
}

/// Simulate a Paddle transaction webhook for testing email and billing flow
#[tracing::instrument(skip_all, err)]
pub(crate) async fn test_simulate_paddle_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulatePaddleTransactionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TestSimulatePaddleTransactionError> {
    use TestSimulatePaddleTransactionErrorCtx as Ctx;

    let transaction_id = req
        .transaction_id
        .unwrap_or_else(|| format!("txn_test_{}", uuid::Uuid::new_v4()));
    let event_type = req
        .event_type
        .unwrap_or_else(|| "transaction.billed".to_string());
    let invoice_number = format!("TEST-{}", transaction_id[9..17].to_uppercase());

    // Ensure the org has a paddle_customer_id in billing_config
    let org_id = req.organization_id.unwrap_or(req.user_id);
    let customer_id = format!("ctm_test_{}", req.user_id);
    if let Err(e) = sqlx::query(
        r#"
        UPDATE billing_config SET paddle_customer_id = $1 WHERE organization_id = $2
        "#,
    )
    .bind(&customer_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    {
        tracing::error!(
            "Failed to update paddle_customer_id for test user {}: {}",
            req.user_id,
            e
        );
    }

    // Build a fake Paddle webhook payload
    let payload = super::webhooks::PaddleWebhookPayload {
        event_id: format!("evt_test_{}", uuid::Uuid::new_v4()),
        event_type: event_type.clone(),
        occurred_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        data: serde_json::json!({
            "id": transaction_id,
            "status": match event_type.as_str() {
                "transaction.completed" => "completed",
                "transaction.payment_failed" => "past_due",
                _ => "billed",
            },
            "customer_id": customer_id,
            "currency_code": "USD",
            "invoice_number": invoice_number,
            "details": {
                "totals": {
                    "total": req.amount_cents.to_string(),
                    "tax": "0"
                }
            },
            "custom_data": req.custom_data.clone().unwrap_or(serde_json::Value::Null)
        }),
    };

    tracing::info!(
        "TEST: Simulating Paddle {} for user {} (${:.2})",
        event_type,
        req.user_id,
        req.amount_cents as f64 / 100.0
    );

    super::webhooks::handle_paddle_transaction_test(&state, payload)
        .await
        .with_context(Ctx::webhook())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "transaction_id": transaction_id,
            "event_type": event_type,
            "invoice_number": invoice_number,
            "amount_cents": req.amount_cents,
            "message": "Paddle transaction processed. Check email service logs for notifications."
        })),
    ))
}

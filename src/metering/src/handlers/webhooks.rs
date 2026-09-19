// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Webhook handlers for Paddle billing events
//!
//! Paddle acts as merchant of record — it handles payment collection,
//! so we no longer need charge_payment_method() or cached balance logic.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::credits::{credit_ledger_once, CreditOutcome};
use crate::AppState;

/// Paddle webhook payload
#[derive(Debug, Deserialize, Serialize)]
pub struct PaddleWebhookPayload {
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub data: serde_json::Value,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PaddleWebhookError {
    #[error("paddle webhook signature verification error [{location}]")]
    SignatureVerification {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid paddle webhook signature [{location}]")]
    InvalidSignature { location: Location },

    #[error("malformed paddle webhook payload [{location}]")]
    MalformedPayload {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("paddle webhook processing failed [{location}]")]
    Processing {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for PaddleWebhookError {
    fn into_response(self) -> Response {
        match self {
            Self::SignatureVerification { .. } | Self::InvalidSignature { .. } => {
                tracing::warn!(error = ?self, "paddle webhook signature rejected");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid signature"})),
                )
                    .into_response()
            }
            Self::MalformedPayload { .. } => {
                tracing::warn!(error = ?self, "malformed paddle webhook payload");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "malformed webhook payload"})),
                )
                    .into_response()
            }
            Self::Processing { .. } => {
                tracing::error!(error = ?self, "paddle webhook processing failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response()
            }
        }
    }
}

/// Handle incoming Paddle webhooks
#[tracing::instrument(skip_all, err)]
pub async fn paddle_webhook_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), PaddleWebhookError> {
    use PaddleWebhookErrorCtx as Ctx;

    match state.paddle.verify_webhook_signature(&headers, &body) {
        Ok(true) => {}
        Ok(false) => {
            return Err(PaddleWebhookError::InvalidSignature {
                location: std::panic::Location::caller(),
            });
        }
        Err(e) => {
            return Err(e).with_context(Ctx::signature_verification());
        }
    }

    let payload: PaddleWebhookPayload =
        serde_json::from_slice(&body).with_context(Ctx::malformed_payload())?;

    tracing::info!(
        "Received Paddle webhook: {} ({})",
        payload.event_type,
        payload.event_id
    );

    let lock_key = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        payload.event_id.hash(&mut hasher);
        hasher.finish() as i64
    };

    let mut tx = state.pool.begin().await.with_context(Ctx::processing())?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::processing())?;

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
    .await
    .with_context(Ctx::processing())?;

    if idempotency_result.rows_affected() == 0 {
        tracing::debug!("Webhook {} already processed, skipping", payload.event_id);
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({"status": "already_processed"})),
        ));
    }

    let result: Result<(), PaddleWebhookError> = match payload.event_type.as_str() {
        "transaction.completed" => handle_transaction_completed(&state, &payload)
            .await
            .map_err(|source| PaddleWebhookError::Processing {
                source: Box::new(source),
                location: std::panic::Location::caller(),
            }),
        "transaction.billed" => {
            handle_transaction_billed(&state, &payload)
                .await
                .map_err(|source| PaddleWebhookError::Processing {
                    source: Box::new(source),
                    location: std::panic::Location::caller(),
                })
        }
        "transaction.payment_failed" => {
            handle_payment_failed(&state, &payload)
                .await
                .map_err(|source| PaddleWebhookError::Processing {
                    source: Box::new(source),
                    location: std::panic::Location::caller(),
                })
        }
        "subscription.created"
        | "subscription.updated"
        | "subscription.activated"
        | "subscription.resumed"
        | "subscription.paused"
        | "subscription.canceled" => {
            handle_subscription_event(&state, &payload)
                .await
                .map_err(|source| PaddleWebhookError::Processing {
                    source: Box::new(source),
                    location: std::panic::Location::caller(),
                })
        }
        _ => {
            tracing::debug!("Ignoring Paddle event type: {}", payload.event_type);
            Ok(())
        }
    };

    result?;

    tx.commit().await.with_context(Ctx::processing())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "processed"})),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum HandleSubscriptionEventErrorKind {
    InvalidSubscriptionId,
    InvalidCustomerId,
    InvalidOccurredAt,
    MissingStatus,
    UnsupportedStatus,
    NoMatchingTier,
    MissingBillingPeriod,
    MissingCustomData,
    MissingOrgMapping,
    MissingCheckoutIntent,
    IntentMismatch,
    AlreadySubscribed,
    CatalogNotConfigured,
    CatalogVersionOverflow,
    Database,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("subscription event processing failed ({kind:?}) [{location}]")]
pub(crate) struct HandleSubscriptionEventError {
    kind: HandleSubscriptionEventErrorKind,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[tracing::instrument(skip_all, err)]
async fn handle_subscription_event(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> Result<(), HandleSubscriptionEventError> {
    use HandleSubscriptionEventErrorCtx as Ctx;

    let data = &payload.data;
    let paddle_subscription_id = data["id"]
        .as_str()
        .filter(|id| id.starts_with("sub_"))
        .ok_or_else(|| HandleSubscriptionEventError {
            kind: HandleSubscriptionEventErrorKind::InvalidSubscriptionId,
            location: std::panic::Location::caller(),
            source: None,
        })?;
    let paddle_customer_id = data["customer_id"]
        .as_str()
        .filter(|id| id.starts_with("ctm_"))
        .ok_or_else(|| HandleSubscriptionEventError {
            kind: HandleSubscriptionEventErrorKind::InvalidCustomerId,
            location: std::panic::Location::caller(),
            source: None,
        })?;
    let occurred_at = DateTime::parse_from_rfc3339(&payload.occurred_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|source| HandleSubscriptionEventError {
            kind: HandleSubscriptionEventErrorKind::InvalidOccurredAt,
            location: std::panic::Location::caller(),
            source: Some(Box::new(source)),
        })?;

    let provider_status = data["status"]
        .as_str()
        .ok_or_else(|| HandleSubscriptionEventError {
            kind: HandleSubscriptionEventErrorKind::MissingStatus,
            location: std::panic::Location::caller(),
            source: None,
        })?;
    let status = match provider_status {
        "active" | "trialing" => "active",
        "past_due" => "past_due",
        "paused" => "paused",
        "canceled" => "canceled",
        _ => {
            return Err(HandleSubscriptionEventError {
                kind: HandleSubscriptionEventErrorKind::UnsupportedStatus,
                location: std::panic::Location::caller(),
                source: None,
            });
        }
    };

    let price_ids: Vec<&str> = data["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["price"]["id"].as_str())
        .collect();
    let matched_tiers: Vec<_> = state
        .pricing
        .subscription_tiers
        .iter()
        .filter(|(_, tier)| {
            tier.paddle_price_id
                .as_deref()
                .is_some_and(|price_id| price_ids.contains(&price_id))
        })
        .collect();
    let (tier_id, tier) = match matched_tiers.as_slice() {
        [(tier_id, tier)] if price_ids.len() == 1 => ((*tier_id).clone(), *tier),
        _ => {
            return Err(HandleSubscriptionEventError {
                kind: HandleSubscriptionEventErrorKind::NoMatchingTier,
                location: std::panic::Location::caller(),
                source: None,
            });
        }
    };

    let period_start = data["current_billing_period"]["starts_at"]
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let period_end = data["current_billing_period"]["ends_at"]
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    if status != "canceled" && (period_start.is_none() || period_end.is_none()) {
        return Err(HandleSubscriptionEventError {
            kind: HandleSubscriptionEventErrorKind::MissingBillingPeriod,
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    let cancel_at_period_end = data["scheduled_change"]["action"].as_str() == Some("cancel");

    let mut tx = state
        .pool
        .begin()
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(paddle_subscription_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;

    let existing = sqlx::query(
        "SELECT id, organization_id, user_id, current_period_start, current_period_end
         FROM subscriptions WHERE paddle_subscription_id = $1 FOR UPDATE",
    )
    .bind(paddle_subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;

    let (subscription_id, organization_id, user_id, effective_start, effective_end) =
        if let Some(row) = existing {
            let current_start: DateTime<Utc> = row.get("current_period_start");
            let current_end: DateTime<Utc> = row.get("current_period_end");
            (
                row.get::<Uuid, _>("id"),
                row.get::<Uuid, _>("organization_id"),
                row.get::<Uuid, _>("user_id"),
                period_start.unwrap_or(current_start),
                period_end.unwrap_or(current_end),
            )
        } else {
            let custom_data =
                data["custom_data"]
                    .as_object()
                    .ok_or_else(|| HandleSubscriptionEventError {
                        kind: HandleSubscriptionEventErrorKind::MissingCustomData,
                        location: std::panic::Location::caller(),
                        source: None,
                    })?;
            let organization_id = custom_data
                .get("caution_organization_id")
                .and_then(|value| value.as_str())
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::MissingOrgMapping,
                    location: std::panic::Location::caller(),
                    source: None,
                })?;
            let intent_id = custom_data
                .get("caution_checkout_intent_id")
                .and_then(|value| value.as_str())
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::MissingCheckoutIntent,
                    location: std::panic::Location::caller(),
                    source: None,
                })?;
            let intent = sqlx::query(
                "SELECT requested_by_user_id, new_tier, new_limit
                 FROM subscription_intents
                 WHERE id = $1 AND organization_id = $2
                   AND operation = 'subscribe'
                   AND status IN ('pending', 'provider_pending')
                 FOR UPDATE",
            )
            .bind(intent_id)
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await
            .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?
            .ok_or_else(|| HandleSubscriptionEventError {
                kind: HandleSubscriptionEventErrorKind::MissingCheckoutIntent,
                location: std::panic::Location::caller(),
                source: None,
            })?;
            if intent.get::<Option<String>, _>("new_tier").as_deref() != Some(tier_id.as_str())
                || intent.get::<Option<i32>, _>("new_limit") != Some(tier.enclaves)
            {
                return Err(HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::IntentMismatch,
                    location: std::panic::Location::caller(),
                    source: None,
                });
            }
            let conflicting_source: Option<String> = sqlx::query_scalar(
                "SELECT billing_source FROM subscriptions
                 WHERE organization_id = $1 AND status <> 'canceled' FOR UPDATE",
            )
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await
            .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
            if conflicting_source.is_some() {
                return Err(HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::AlreadySubscribed,
                    location: std::panic::Location::caller(),
                    source: None,
                });
            }
            (
                Uuid::new_v4(),
                organization_id,
                intent.get::<Uuid, _>("requested_by_user_id"),
                period_start.ok_or_else(|| HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::MissingBillingPeriod,
                    location: std::panic::Location::caller(),
                    source: None,
                })?,
                period_end.ok_or_else(|| HandleSubscriptionEventError {
                    kind: HandleSubscriptionEventErrorKind::MissingBillingPeriod,
                    location: std::panic::Location::caller(),
                    source: None,
                })?,
            )
        };

    let catalog_version = i32::try_from(
        state
            .pricing
            .paddle_catalog
            .as_ref()
            .ok_or_else(|| HandleSubscriptionEventError {
                kind: HandleSubscriptionEventErrorKind::CatalogNotConfigured,
                location: std::panic::Location::caller(),
                source: None,
            })?
            .version,
    )
    .map_err(|source| HandleSubscriptionEventError {
        kind: HandleSubscriptionEventErrorKind::CatalogVersionOverflow,
        location: std::panic::Location::caller(),
        source: Some(Box::new(source)),
    })?;
    let projection = sqlx::query(
        "INSERT INTO subscriptions
         (id, user_id, organization_id, tier, max_vcpus, max_apps,
          price_cents_per_cycle, status, billing_source, paddle_customer_id,
          paddle_subscription_id, paddle_price_id, catalog_version, catalog_valid,
          current_period_start, current_period_end, next_billing_at,
          cancel_at_period_end, canceled_at, provider_occurred_at)
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7, 'paddle', $8, $9, $10,
                 $11, true, $12, $13, $13, $14,
                 CASE WHEN $7 = 'canceled' THEN $15 ELSE NULL END, $15)
         ON CONFLICT (paddle_subscription_id) WHERE paddle_subscription_id IS NOT NULL
         DO UPDATE SET tier = EXCLUDED.tier,
                       max_apps = EXCLUDED.max_apps,
                       price_cents_per_cycle = EXCLUDED.price_cents_per_cycle,
                       status = EXCLUDED.status,
                       paddle_customer_id = EXCLUDED.paddle_customer_id,
                       paddle_price_id = EXCLUDED.paddle_price_id,
                       catalog_version = EXCLUDED.catalog_version,
                       catalog_valid = EXCLUDED.catalog_valid,
                       current_period_start = EXCLUDED.current_period_start,
                       current_period_end = EXCLUDED.current_period_end,
                       next_billing_at = EXCLUDED.next_billing_at,
                       cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                       canceled_at = EXCLUDED.canceled_at,
                       provider_occurred_at = EXCLUDED.provider_occurred_at,
                       updated_at = NOW()
         WHERE subscriptions.provider_occurred_at IS NULL
            OR subscriptions.provider_occurred_at < EXCLUDED.provider_occurred_at
            OR (
                subscriptions.provider_occurred_at = EXCLUDED.provider_occurred_at
                AND CASE EXCLUDED.status
                    WHEN 'canceled' THEN 4
                    WHEN 'paused' THEN 3
                    WHEN 'past_due' THEN 2
                    WHEN 'active' THEN 1
                    ELSE 0
                END > CASE subscriptions.status
                    WHEN 'canceled' THEN 4
                    WHEN 'paused' THEN 3
                    WHEN 'past_due' THEN 2
                    WHEN 'active' THEN 1
                    ELSE 0
                END
            )",
    )
    .bind(subscription_id)
    .bind(user_id)
    .bind(organization_id)
    .bind(&tier_id)
    .bind(tier.enclaves)
    .bind(tier.monthly_cents())
    .bind(status)
    .bind(paddle_customer_id)
    .bind(paddle_subscription_id)
    .bind(tier.paddle_price_id.as_deref())
    .bind(catalog_version)
    .bind(effective_start)
    .bind(effective_end)
    .bind(cancel_at_period_end)
    .bind(occurred_at)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    if projection.rows_affected() == 0 {
        return Ok(());
    }

    if let Some(intent_id) = data["custom_data"]["caution_checkout_intent_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        sqlx::query(
            "UPDATE subscription_intents
             SET status = 'applied', applied_at = NOW(), paddle_subscription_id = $1, updated_at = NOW()
             WHERE id = $2 AND organization_id = $3 AND operation = 'subscribe'
               AND status IN ('pending', 'provider_pending')",
        )
        .bind(paddle_subscription_id)
        .bind(intent_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    }
    if let Some(intent_id) = data["custom_data"]["caution_change_intent_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        let applied = sqlx::query(
            "UPDATE subscription_intents SET status = 'applied', applied_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND subscription_id = $3
               AND operation IN ('upgrade', 'downgrade') AND status = 'provider_pending'",
        )
        .bind(intent_id)
        .bind(organization_id)
        .bind(subscription_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
        if applied.rows_affected() == 1 {
            sqlx::query(
                "UPDATE subscriptions SET pending_tier = NULL, pending_max_apps = NULL, updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(subscription_id)
            .execute(&mut *tx)
            .await
            .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
        }
    }
    if cancel_at_period_end || status == "canceled" {
        sqlx::query(
            "UPDATE subscription_intents SET status = 'applied', applied_at = NOW(), updated_at = NOW()
             WHERE organization_id = $1 AND paddle_subscription_id = $2
               AND operation = 'cancel' AND status = 'provider_pending'",
        )
        .bind(organization_id)
        .bind(paddle_subscription_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    }
    sqlx::query(
        "INSERT INTO billing_config (organization_id, paddle_customer_id, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (organization_id) DO UPDATE
         SET paddle_customer_id = EXCLUDED.paddle_customer_id, updated_at = NOW()",
    )
    .bind(organization_id)
    .bind(paddle_customer_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    tx.commit()
        .await
        .with_context(Ctx::new(HandleSubscriptionEventErrorKind::Database))?;
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ClearCreditSuspensionError {
    #[error("could not clear credit suspension [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn clear_credit_suspension_if_needed(
    state: &AppState,
    org_id: uuid::Uuid,
    new_balance: i64,
) -> Result<(), ClearCreditSuspensionError> {
    use ClearCreditSuspensionErrorCtx as Ctx;

    if new_balance <= 0 {
        return Ok(());
    }

    let suspended: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await
            .with_context(Ctx::database())?
            .flatten();

    if suspended.is_none() {
        return Ok(());
    }

    tracing::info!(
        "Clearing credit suspension for org {} after completed Paddle credit transaction",
        org_id
    );
    sqlx::query("UPDATE organizations SET credit_suspended_at = NULL WHERE id = $1")
        .bind(org_id)
        .execute(&state.pool)
        .await
        .with_context(Ctx::database())?;

    let unsuspend_user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .with_context(Ctx::database())?;

    if let Some(uid) = unsuspend_user_id {
        let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let _ = client
            .post(format!("{}/internal/org/{}/unsuspend", api_url, org_id))
            .header(
                "x-internal-service-secret",
                state.internal_service_secret.as_str(),
            )
            .header("x-authenticated-user-id", uid.to_string())
            .send()
            .await;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum HandleTransactionCompletedError {
    #[error("could not process completed transaction [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Handle transaction.completed — payment was collected successfully
#[tracing::instrument(skip_all, err)]
async fn handle_transaction_completed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> Result<(), HandleTransactionCompletedError> {
    use HandleTransactionCompletedErrorCtx as Ctx;

    let transaction_id = payload.data["id"].as_str().unwrap_or_default();
    let customer_id = payload.data["customer_id"].as_str().unwrap_or_default();

    tracing::info!(
        "Transaction completed: {} for customer {}",
        transaction_id,
        customer_id
    );

    let org_row =
        sqlx::query("SELECT organization_id FROM billing_config WHERE paddle_customer_id = $1")
            .bind(customer_id)
            .fetch_optional(&state.pool)
            .await
            .with_context(Ctx::database())?;

    let Some(org_row) = org_row else {
        tracing::warn!(
            "No billing_config found for paddle_customer_id: {}",
            customer_id
        );
        return Ok(());
    };

    let org_id: uuid::Uuid = org_row.get("organization_id");

    sqlx::query(
        r#"
        UPDATE invoices
        SET payment_status = 'succeeded', paid_at = NOW()
        WHERE paddle_transaction_id = $1
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    if let Err(e) = sqlx::query(
        r#"
        UPDATE subscription_ledger sl
        SET status = 'paid'
        FROM invoices i
        WHERE sl.invoice_id = i.id
          AND i.paddle_transaction_id = $1
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await
    {
        tracing::error!(
            "Failed to mark billing event as paid for txn {}: {}",
            transaction_id,
            e
        );
    }

    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .with_context(Ctx::database())?;

    if let Some(user_id) = user_id {
        send_payment_confirmation_email(state, user_id, transaction_id)
            .await
            .with_context(Ctx::database())?;
    }

    let intent = sqlx::query(
        "SELECT organization_id, user_id, credit_cents FROM credit_purchase_intents WHERE paddle_transaction_id = $1",
    )
    .bind(transaction_id)
    .fetch_optional(&state.pool)
    .await
    .with_context(Ctx::database())?;

    if let Some(intent) = intent {
        let intent_org_id: uuid::Uuid = intent.get("organization_id");
        let intent_user_id: uuid::Uuid = intent.get("user_id");
        let credit_cents: i64 = intent.get("credit_cents");

        if intent_org_id != org_id {
            tracing::error!(
                "Credit purchase intent org {} does not match resolved org {} for txn {}; refusing to credit",
                intent_org_id,
                org_id,
                transaction_id
            );
            return Ok(());
        }

        match credit_ledger_once(
            &state.pool,
            org_id,
            Some(intent_user_id),
            credit_cents,
            "purchase",
            &format!(
                "Prepaid credit purchase: ${:.2}",
                credit_cents as f64 / 100.0
            ),
            transaction_id,
        )
        .await
        .with_context(Ctx::database())?
        {
            CreditOutcome::AlreadyCredited => {
                tracing::info!(
                    "Prepaid credit purchase {} already credited, skipping",
                    transaction_id
                );
            }
            CreditOutcome::Credited { new_balance } => {
                tracing::info!(
                    "Prepaid credit purchase credited: org={}, txn={}, +{}c, new_balance={}",
                    org_id,
                    transaction_id,
                    credit_cents,
                    new_balance
                );
                clear_credit_suspension_if_needed(state, org_id, new_balance)
                    .await
                    .with_context(Ctx::database())?;
            }
        }
        return Ok(());
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum HandleTransactionBilledError {
    #[error("could not process billed transaction [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Handle transaction.billed — invoice was created/issued
#[tracing::instrument(skip_all, err)]
async fn handle_transaction_billed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> Result<(), HandleTransactionBilledError> {
    use HandleTransactionBilledErrorCtx as Ctx;

    let transaction_id = payload.data["id"].as_str().unwrap_or_default();
    let customer_id = payload.data["customer_id"].as_str().unwrap_or_default();
    let total = payload.data["details"]["totals"]["total"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let tax = payload.data["details"]["totals"]["tax"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let currency = payload.data["currency_code"].as_str().unwrap_or("USD");
    let invoice_number = payload.data["invoice_number"].as_str().unwrap_or("");

    tracing::info!(
        "Transaction billed: {} ({} cents) for customer {}",
        transaction_id,
        total,
        customer_id
    );

    let user_row =
        sqlx::query("SELECT organization_id FROM billing_config WHERE paddle_customer_id = $1")
            .bind(customer_id)
            .fetch_optional(&state.pool)
            .await
            .with_context(Ctx::database())?;

    let Some(user_row) = user_row else {
        tracing::warn!(
            "No billing_config found for paddle_customer_id: {}",
            customer_id
        );
        return Ok(());
    };

    let org_id: uuid::Uuid = user_row.get("organization_id");

    let invoice_user_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .with_context(Ctx::database())?;

    sqlx::query(
        r#"
        INSERT INTO invoices (
            paddle_transaction_id, user_id, organization_id, invoice_number,
            amount_cents, tax_amount_cents, currency,
            status, payment_status, billing_provider, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'finalized', 'pending', 'paddle', NOW())
        ON CONFLICT (paddle_transaction_id) DO UPDATE SET
            status = 'finalized',
            payment_status = 'pending',
            amount_cents = $5,
            tax_amount_cents = $6
        "#,
    )
    .bind(transaction_id)
    .bind(invoice_user_id)
    .bind(org_id)
    .bind(invoice_number)
    .bind(total)
    .bind(tax)
    .bind(currency)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    send_invoice_email(
        state,
        invoice_user_id,
        transaction_id,
        total,
        invoice_number,
    )
    .await
    .with_context(Ctx::database())?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum HandlePaymentFailedError {
    #[error("could not process failed payment [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Handle transaction.payment_failed — payment collection failed
#[tracing::instrument(skip_all, err)]
async fn handle_payment_failed(
    state: &AppState,
    payload: &PaddleWebhookPayload,
) -> Result<(), HandlePaymentFailedError> {
    use HandlePaymentFailedErrorCtx as Ctx;

    let transaction_id = payload.data["id"].as_str().unwrap_or_default();
    let customer_id = payload.data["customer_id"].as_str().unwrap_or_default();

    tracing::warn!(
        "Transaction payment failed: {} for customer {}",
        transaction_id,
        customer_id
    );

    let user_row =
        sqlx::query("SELECT organization_id FROM billing_config WHERE paddle_customer_id = $1")
            .bind(customer_id)
            .fetch_optional(&state.pool)
            .await
            .with_context(Ctx::database())?;

    let Some(user_row) = user_row else {
        return Ok(());
    };

    let org_id: uuid::Uuid = user_row.get("organization_id");

    let user_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(org_id);

    sqlx::query(
        r#"UPDATE invoices SET payment_status = 'failed' WHERE paddle_transaction_id = $1"#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    if let Err(e) = sqlx::query(
        r#"
        UPDATE subscriptions SET status = 'past_due', updated_at = NOW()
        WHERE id IN (
            SELECT sl.subscription_id
            FROM subscription_ledger sl
            JOIN invoices i ON sl.invoice_id = i.id
            WHERE i.paddle_transaction_id = $1
        )
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await
    {
        tracing::error!(
            "Failed to mark subscription as past_due for txn {}: {}",
            transaction_id,
            e
        );
    }

    if let Err(e) = sqlx::query(
        r#"
        UPDATE subscription_ledger sl
        SET status = 'payment_failed'
        FROM invoices i
        WHERE sl.invoice_id = i.id
          AND i.paddle_transaction_id = $1
        "#,
    )
    .bind(transaction_id)
    .execute(&state.pool)
    .await
    {
        tracing::error!(
            "Failed to mark billing event as payment_failed for txn {}: {}",
            transaction_id,
            e
        );
    }

    send_payment_failure_email(state, user_id, transaction_id)
        .await
        .with_context(Ctx::database())?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum HandlePaddleTransactionTestError {
    #[error("paddle transaction test handler failed [{location}]")]
    Wrapped {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Public entry point for test simulation
#[tracing::instrument(skip_all, err)]
pub async fn handle_paddle_transaction_test(
    state: &AppState,
    payload: PaddleWebhookPayload,
) -> Result<(), HandlePaddleTransactionTestError> {
    use HandlePaddleTransactionTestErrorCtx as Ctx;

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
    .await
    {
        tracing::error!(
            "Failed to record test webhook event {}: {}",
            payload.event_id,
            e
        );
    }

    match payload.event_type.as_str() {
        "transaction.completed" => handle_transaction_completed(state, &payload)
            .await
            .with_context(Ctx::wrapped())?,
        "transaction.billed" => handle_transaction_billed(state, &payload)
            .await
            .with_context(Ctx::wrapped())?,
        "transaction.payment_failed" => handle_payment_failed(state, &payload)
            .await
            .with_context(Ctx::wrapped())?,
        _ => {}
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SendInvoiceEmailError {
    #[error("could not query user for invoice email [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn send_invoice_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
    amount_cents: i64,
    invoice_number: &str,
) -> Result<(), SendInvoiceEmailError> {
    use SendInvoiceEmailErrorCtx as Ctx;

    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .with_context(Ctx::database())?;

    let Some(user) = user else {
        tracing::warn!("User {} not found for invoice email", user_id);
        return Ok(());
    };

    let email: Option<String> = user.get("email");

    let Some(email) = email else {
        tracing::warn!(
            "User {} has no email address, skipping invoice email",
            user_id
        );
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

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SendPaymentConfirmationEmailError {
    #[error("could not query user for payment confirmation email [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn send_payment_confirmation_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
) -> Result<(), SendPaymentConfirmationEmailError> {
    use SendPaymentConfirmationEmailErrorCtx as Ctx;

    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .with_context(Ctx::database())?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: Option<String> = user.get("email");
    let Some(email) = email else {
        tracing::warn!(
            "User {} has no email, skipping payment confirmation",
            user_id
        );
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

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SendPaymentFailureEmailError {
    #[error("could not query user for payment failure email [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn send_payment_failure_email(
    state: &AppState,
    user_id: uuid::Uuid,
    transaction_id: &str,
) -> Result<(), SendPaymentFailureEmailError> {
    use SendPaymentFailureEmailErrorCtx as Ctx;

    let user = sqlx::query(r#"SELECT email FROM users WHERE id = $1"#)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .with_context(Ctx::database())?;

    let Some(user) = user else {
        return Ok(());
    };

    let email: Option<String> = user.get("email");
    let Some(email) = email else {
        tracing::warn!(
            "User {} has no email, skipping payment failure email",
            user_id
        );
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
        assert_eq!(
            payload.data["invoice_number"].as_str().unwrap(),
            "INV-2025-001"
        );
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
    }
}

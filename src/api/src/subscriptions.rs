use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use crate::{AppState, AuthContext, can_manage_org, check_org_access, get_user_primary_org};

fn paddle_subscriptions_enabled() -> bool {
    std::env::var("BYOC_PADDLE_SUBSCRIPTIONS_ENABLED")
        .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
}

async fn require_billing_manager(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    let role = check_org_access(&state.db, user_id, org_id)
        .await
        .map_err(|status| (status, "Organization access denied".to_string()))?;
    if !can_manage_org(&role) {
        return Err((
            StatusCode::FORBIDDEN,
            "Organization owner or administrator access is required".to_string(),
        ));
    }
    Ok(())
}

fn paddle_http_client() -> Result<reqwest::Client, (StatusCode, String)> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to initialize Paddle client".to_string(),
            )
        })
}

async fn paddle_json_request(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<&serde_json::Value>,
    idempotency_key: Option<Uuid>,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let api_key = state.paddle_api_key.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle API is not configured".to_string(),
        )
    })?;
    if state.paddle_api_url != "https://sandbox-api.paddle.com"
        && state.paddle_api_url != "https://api.paddle.com"
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle API origin is not configured safely".to_string(),
        ));
    }
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid Paddle API path".to_string(),
        ));
    }

    let client = paddle_http_client()?;
    let mut request = client
        .request(method, format!("{}{}", state.paddle_api_url, path))
        .bearer_auth(api_key)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(idempotency_key) = idempotency_key {
        request = request.header("Paddle-Idempotency-Key", idempotency_key.to_string());
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|error| {
        tracing::warn!(error = %error, path, "Paddle request failed");
        (
            StatusCode::BAD_GATEWAY,
            "Paddle is temporarily unavailable".to_string(),
        )
    })?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Unable to read Paddle response".to_string(),
        )
    })?;
    if bytes.len() > 1_048_576 {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Paddle response exceeded the allowed size".to_string(),
        ));
    }
    if !status.is_success() {
        tracing::warn!(%status, path, "Paddle API returned an error");
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Paddle request failed with status {status}"),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "Paddle returned an invalid response".to_string(),
        )
    })
}

pub(crate) fn tier_display_name(id: &str) -> String {
    id.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn resolved_subscription_values(
    pricing: &crate::PricingConfig,
    tier_id: &str,
    stored_max_apps: i32,
    stored_price_cents: i64,
) -> (String, i32, i64) {
    if let Some(tier) = pricing.subscription_tiers.get(tier_id) {
        (
            tier_display_name(tier_id),
            tier.enclaves,
            tier.monthly_cents(),
        )
    } else {
        (
            tier_display_name(tier_id),
            stored_max_apps,
            stored_price_cents,
        )
    }
}

async fn close_open_subscription_segment(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    subscription_id: Uuid,
    period_end: DateTime<Utc>,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "UPDATE subscription_ledger
         SET billing_period_end = $1
         WHERE subscription_id = $2
           AND billing_period_end IS NULL
           AND billing_period_start < $1",
    )
    .bind(period_end)
    .bind(subscription_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    Ok(())
}

pub async fn get_subscription_tiers(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut tier_entries: Vec<(&String, &crate::TierPricing)> =
        state.pricing.subscription_tiers.iter().collect();
    tier_entries.sort_by_key(|(id, tier)| (tier.enclaves, id.as_str()));

    let tiers: Vec<serde_json::Value> = tier_entries
        .iter()
        .map(|(id, t)| {
            serde_json::json!({
                "id": id,
                "name": tier_display_name(id),
                "enclaves": t.enclaves,
                "price_cents_per_cycle": t.monthly_cents(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "tiers": tiers })))
}

pub async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let row = sqlx::query(
        "SELECT s.id, s.user_id, s.organization_id, s.tier, s.max_vcpus, s.max_apps,
                s.price_cents_per_cycle, s.status, s.billing_source, s.pending_tier,
                s.pending_max_apps, s.catalog_valid, s.enterprise_expires_at,
                s.started_at, s.current_period_start, s.current_period_end, s.canceled_at,
                s.cancel_at_period_end, s.last_billed_at, s.next_billing_at, s.created_at,
                s.updated_at,
                (SELECT COUNT(*) FROM compute_resources cr
                 JOIN cloud_credentials cc ON cc.resource_id = cr.id
                 WHERE cr.organization_id = s.organization_id
                   AND cc.managed_on_prem = true
                   AND cr.destroyed_at IS NULL
                   AND cr.state NOT IN ('terminated', 'failed')) AS allocated_enclaves
         FROM subscriptions s
         WHERE s.organization_id = $1 AND s.status <> 'canceled'
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let Some(row) = row else {
        return Ok(Json(serde_json::json!({ "subscription": null })));
    };

    let tier: String = row.get("tier");
    let (tier_name, max_apps, price_cents_per_cycle) = resolved_subscription_values(
        &state.pricing,
        &tier,
        row.get("max_apps"),
        row.get("price_cents_per_cycle"),
    );

    let billing_source: String = row.get("billing_source");
    let pending_tier: Option<String> = row.get("pending_tier");
    let pending_max_apps: Option<i32> = row.get("pending_max_apps");
    let monthly_price = if billing_source == "enterprise" {
        None
    } else {
        Some(price_cents_per_cycle)
    };

    Ok(Json(serde_json::json!({
        "subscription": {
            "id": row.get::<Uuid, _>("id"),
            "user_id": row.get::<Uuid, _>("user_id"),
            "organization_id": row.get::<Uuid, _>("organization_id"),
            "source": billing_source,
            "tier": tier,
            "tier_id": tier,
            "tier_name": tier_name,
            "billing_period": "monthly",
            "enclaves": max_apps,
            "max_apps": max_apps,
            "enclave_limit": max_apps,
            "allocated_enclaves": row.get::<i64, _>("allocated_enclaves"),
            "pending_enclave_limit": pending_max_apps,
            "pending_change": pending_tier.map(|tier_id| serde_json::json!({
                "tier_id": tier_id,
                "enclave_limit": pending_max_apps,
            })),
            "price_cents_per_cycle": monthly_price,
            "monthly_price_cents": monthly_price,
            "total_price_cents_per_cycle": monthly_price,
            "status": row.get::<String, _>("status"),
            "catalog_valid": row.get::<bool, _>("catalog_valid"),
            "enterprise_expires_at": row.get::<Option<DateTime<Utc>>, _>("enterprise_expires_at"),
            "started_at": row.get::<DateTime<Utc>, _>("started_at"),
            "current_period_start": row.get::<DateTime<Utc>, _>("current_period_start"),
            "current_period_end": row.get::<DateTime<Utc>, _>("current_period_end"),
            "canceled_at": row.get::<Option<DateTime<Utc>>, _>("canceled_at"),
            "cancel_at_period_end": row.get::<bool, _>("cancel_at_period_end"),
            "last_billed_at": row.get::<Option<DateTime<Utc>>, _>("last_billed_at"),
            "next_billing_at": row.get::<DateTime<Utc>, _>("next_billing_at"),
            "created_at": row.get::<DateTime<Utc>, _>("created_at"),
            "updated_at": row.get::<DateTime<Utc>, _>("updated_at"),
        }
    })))
}

#[derive(Deserialize)]
pub struct SubscribeRequest {
    tier_id: String,
}

const LEGACY_MAX_VCPUS_PLACEHOLDER: i32 = 0;

pub async fn checkout_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !paddle_subscriptions_enabled() {
        return Err((
            StatusCode::NOT_FOUND,
            "Paddle subscriptions are not enabled".to_string(),
        ));
    }

    let tier = state
        .pricing
        .subscription_tiers
        .get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;
    let price_id = tier.paddle_price_id.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Selected tier is not available in Paddle".to_string(),
        )
    })?;
    let catalog_version = state
        .pricing
        .paddle_catalog
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Paddle catalog is not configured".to_string(),
            )
        })?
        .version;
    let client_token = state.paddle_client_token.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle checkout is not configured".to_string(),
        )
    })?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|status| (status, "Failed to get organization".to_string()))?;
    require_billing_manager(&state, auth.user_id, org_id).await?;

    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to start subscription checkout".to_string(),
        )
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription checkout".to_string(),
            )
        })?;

    sqlx::query(
        "UPDATE subscription_intents SET status = 'canceled', updated_at = NOW()
         WHERE organization_id = $1 AND status = 'pending'
           AND expires_at <= NOW()",
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to expire stale subscription checkout".to_string(),
        )
    })?;

    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE organization_id = $1 AND status <> 'canceled')",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to inspect subscription state".to_string(),
        )
    })?;
    if existing {
        return Err((
            StatusCode::CONFLICT,
            "Organization already has a subscription".to_string(),
        ));
    }

    let pending: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, paddle_transaction_id, new_tier FROM subscription_intents
         WHERE organization_id = $1 AND operation = 'subscribe'
           AND status IN ('pending', 'provider_pending') AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to inspect pending checkout".to_string(),
        )
    })?;
    let intent_id = if let Some((intent_id, transaction_id, pending_tier)) = pending {
        if pending_tier.as_deref() != Some(req.tier_id.as_str()) {
            return Err((
                StatusCode::CONFLICT,
                "A subscription checkout for another tier is already pending".to_string(),
            ));
        }
        if let Some(transaction_id) = transaction_id {
            tx.commit().await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to finish checkout lookup".to_string(),
                )
            })?;
            return Ok(Json(serde_json::json!({
                "intent_id": intent_id,
                "transaction_id": transaction_id,
                "client_token": client_token,
                "status": "provider_pending",
            })));
        }
        tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to finish checkout retry lookup".to_string(),
            )
        })?;
        intent_id
    } else {
        let intent_id: Uuid = sqlx::query_scalar(
            "INSERT INTO subscription_intents
             (organization_id, requested_by_user_id, operation, new_tier, new_limit)
             VALUES ($1, $2, 'subscribe', $3, $4) RETURNING id",
        )
        .bind(org_id)
        .bind(auth.user_id)
        .bind(&req.tier_id)
        .bind(tier.enclaves)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create subscription checkout intent".to_string(),
            )
        })?;
        tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist subscription checkout intent".to_string(),
            )
        })?;
        intent_id
    };

    let mut body = serde_json::json!({
        "items": [{"price_id": price_id, "quantity": 1}],
        "collection_mode": "automatic",
        "custom_data": {
            "caution_operation": "byoc_subscription",
            "caution_checkout_intent_id": intent_id.to_string(),
            "caution_organization_id": org_id.to_string(),
            "caution_tier_id": req.tier_id,
            "caution_catalog_version": catalog_version,
        }
    });
    let customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to read Paddle customer mapping".to_string(),
        )
    })?
    .flatten();
    if let Some(customer_id) = customer_id {
        body["customer_id"] = serde_json::Value::String(customer_id);
    }

    let response = match paddle_json_request(
        &state,
        reqwest::Method::POST,
        "/transactions",
        Some(&body),
        Some(intent_id),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            // A timeout or response-read failure does not prove Paddle rejected the
            // transaction. Retain the same intent and idempotency key so a retry
            // cannot create a second billable checkout.
            let _ = sqlx::query(
                "UPDATE subscription_intents
                 SET status = 'provider_pending', expires_at = GREATEST(expires_at, NOW() + INTERVAL '24 hours'), updated_at = NOW()
                 WHERE id = $1 AND status IN ('pending', 'provider_pending')",
            )
            .bind(intent_id)
            .execute(&state.db)
            .await;
            return Err(error);
        }
    };
    let transaction_id = response["data"]["id"]
        .as_str()
        .filter(|id| id.starts_with("txn_"))
        .ok_or_else(|| {
            (
                StatusCode::BAD_GATEWAY,
                "Paddle response did not contain a transaction ID".to_string(),
            )
        })?;

    let persisted = sqlx::query(
        "UPDATE subscription_intents
         SET paddle_transaction_id = $1, status = 'provider_pending', updated_at = NOW()
         WHERE id = $2 AND status IN ('pending', 'provider_pending')",
    )
    .bind(transaction_id)
    .bind(intent_id)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist Paddle transaction ID".to_string(),
        )
    })?
    .rows_affected();
    if persisted != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Subscription checkout intent is no longer pending".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "intent_id": intent_id,
        "transaction_id": transaction_id,
        "client_token": client_token,
        "status": "provider_pending",
    })))
}

async fn change_paddle_subscription(
    state: &AppState,
    auth: &AuthContext,
    organization_id: Uuid,
    subscription_id: Uuid,
    paddle_subscription_id: &str,
    old_limit: i32,
    new_tier_id: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_billing_manager(state, auth.user_id, organization_id).await?;
    let new_tier = state
        .pricing
        .subscription_tiers
        .get(new_tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;
    let price_id = new_tier.paddle_price_id.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Selected tier is not available in Paddle".to_string(),
        )
    })?;
    if new_tier.enclaves < old_limit {
        let allocated: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc ON cc.resource_id = cr.id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.destroyed_at IS NULL
               AND cr.state NOT IN ('terminated', 'failed')",
        )
        .bind(organization_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to inspect allocated BYOC resources".to_string(),
            )
        })?;
        if allocated > i64::from(new_tier.enclaves) {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "Cannot change to a {}-enclave plan while {} enclaves are allocated",
                    new_tier.enclaves, allocated
                ),
            ));
        }
    }

    sqlx::query(
        "UPDATE subscription_intents SET status = 'canceled', updated_at = NOW()
         WHERE organization_id = $1 AND status = 'pending'
           AND expires_at <= NOW()",
    )
    .bind(organization_id)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to expire stale subscription changes".to_string(),
        )
    })?;

    let operation = if new_tier.enclaves > old_limit {
        "upgrade"
    } else {
        "downgrade"
    };
    let intent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO subscription_intents
         (organization_id, requested_by_user_id, operation, subscription_id,
          paddle_subscription_id, old_limit, new_tier, new_limit)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(organization_id)
    .bind(auth.user_id)
    .bind(operation)
    .bind(subscription_id)
    .bind(paddle_subscription_id)
    .bind(old_limit)
    .bind(new_tier_id)
    .bind(new_tier.enclaves)
    .fetch_one(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Another subscription change is already pending".to_string(),
        )
    })?;

    let mut pending_tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?;
    let claimed = sqlx::query(
        "UPDATE subscription_intents SET status = 'provider_pending', updated_at = NOW()
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(intent_id)
    .execute(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?
    .rows_affected();
    if claimed != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Subscription change is no longer pending".to_string(),
        ));
    }
    sqlx::query(
        "UPDATE subscriptions SET pending_tier = $1, pending_max_apps = $2, updated_at = NOW()
         WHERE id = $3",
    )
    .bind(new_tier_id)
    .bind(new_tier.enclaves)
    .bind(subscription_id)
    .execute(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?;
    pending_tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?;

    let path = format!("/subscriptions/{paddle_subscription_id}");
    let body = serde_json::json!({
        "items": [{"price_id": price_id, "quantity": 1}],
        "proration_billing_mode": if new_tier.enclaves > old_limit {
            "prorated_immediately"
        } else {
            "do_not_bill"
        },
        "on_payment_failure": "prevent_change",
        "custom_data": {
            "caution_operation": "byoc_subscription",
            "caution_change_intent_id": intent_id.to_string(),
            "caution_organization_id": organization_id.to_string(),
            "caution_tier_id": new_tier_id,
        },
    });
    if let Err(error) = paddle_json_request(
        state,
        reqwest::Method::PATCH,
        &path,
        Some(&body),
        Some(intent_id),
    )
    .await
    {
        // A transport error does not prove Paddle rejected the change. Keep the
        // provider-pending projection so a delayed webhook can reconcile it and
        // so a second, potentially duplicate paid change cannot be submitted.
        return Err(error);
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "intent_id": intent_id,
        "new_tier": new_tier_id,
        "new_price_cents_per_cycle": new_tier.monthly_cents(),
        "effective": "pending_webhook",
    })))
}

pub async fn subscribe(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if paddle_subscriptions_enabled() {
        return checkout_subscription(State(state), Extension(auth), Json(req)).await;
    }

    let tier = state
        .pricing
        .subscription_tiers
        .get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Check no existing active subscription
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM subscriptions WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            "Organization already has an active subscription".to_string(),
        ));
    }

    let balance_cents = crate::billing::get_ledger_balance_cents(&state.db, org_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    let now = Utc::now();
    let price_per_cycle = tier.monthly_cents();
    let cost_hourly = state
        .pricing
        .subscription_cost_hourly_usd(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    if balance_cents <= f64::round(cost_hourly * 100. * 24.) as i64 {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "insufficient_balance".to_string(),
        ));
    }

    let mut tx = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let sub_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO subscriptions (
             user_id, organization_id, tier, billing_period, max_vcpus, max_apps,
             price_cents_per_cycle, extra_vcpu_blocks, extra_app_blocks,
             extra_block_price_cents_per_cycle, current_period_end, next_billing_at
         )
         VALUES ($1, $2, $3, 'monthly', $4, $5, $6, 0, 0, 0, $7, TIMESTAMPTZ '9999-12-31 23:59:59+00')
         RETURNING id",
    )
    .bind(auth.user_id)
    .bind(org_id)
    .bind(&req.tier_id)
    .bind(LEGACY_MAX_VCPUS_PLACEHOLDER)
    .bind(tier.enclaves)
    .bind(price_per_cycle)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create subscription: {}", e),
        )
    })?;

    sqlx::query(
        "INSERT INTO subscription_ledger
         (subscription_id, organization_id, billing_period_start, billing_period_end, tier, cost_hourly, invoice_id, status)
         VALUES ($1, $2, $3, NULL, $4, $5, NULL, 'credits_covered')"
    )
    .bind(sub_id.0)
    .bind(org_id)
    .bind(now)
    .bind(&req.tier_id)
    .bind(cost_hourly)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record billing event: {}", e)))?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit: {}", e),
        )
    })?;

    tracing::info!(
        "Subscription created: sub={}, tier={}, org={}, opening_balance={} cents",
        sub_id.0,
        req.tier_id,
        org_id,
        balance_cents
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "subscription_id": sub_id.0,
        "tier": req.tier_id,
        "billing_period": "monthly",
        "price_cents_per_cycle": price_per_cycle,
        "credits_applied": 0,
        "charged": 0,
    })))
}

#[derive(Deserialize)]
pub struct ChangeTierRequest {
    tier_id: String,
}

pub async fn change_subscription_tier(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ChangeTierRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let new_tier = state
        .pricing
        .subscription_tiers
        .get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    require_billing_manager(&state, auth.user_id, org_id).await?;

    let sub: Option<(Uuid, String, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT id, tier, billing_source, paddle_subscription_id, max_apps
         FROM subscriptions WHERE organization_id = $1 AND status <> 'canceled' LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to read subscription".to_string(),
        )
    })?;

    let Some((sub_id, old_tier_id, billing_source, paddle_subscription_id, old_limit)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    if old_tier_id == req.tier_id {
        return Err((StatusCode::BAD_REQUEST, "Already on this tier".to_string()));
    }
    if billing_source == "enterprise" {
        return Err((
            StatusCode::CONFLICT,
            "Enterprise entitlements must be changed by an operator".to_string(),
        ));
    }
    if billing_source == "paddle" {
        let paddle_subscription_id = paddle_subscription_id
            .filter(|id| id.starts_with("sub_"))
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Paddle subscription mapping is invalid".to_string(),
                )
            })?;
        return change_paddle_subscription(
            &state,
            &auth,
            org_id,
            sub_id,
            &paddle_subscription_id,
            old_limit,
            &req.tier_id,
        )
        .await;
    }

    let now = Utc::now();
    let new_price = new_tier.monthly_cents();
    let new_cost_hourly = state
        .pricing
        .subscription_cost_hourly_usd(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    let mut tx = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let current_ledger: Option<(DateTime<Utc>, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT billing_period_start, invoice_id, status
         FROM subscription_ledger
         WHERE subscription_id = $1
           AND billing_period_start <= $2
           AND (billing_period_end IS NULL OR billing_period_end > $2)
         ORDER BY billing_period_start DESC
         LIMIT 1",
    )
    .bind(sub_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let latest_ledger_metadata: Option<(Option<Uuid>, String)> = if current_ledger.is_none() {
        sqlx::query_as(
            "SELECT invoice_id, status
             FROM subscription_ledger
             WHERE subscription_id = $1
             ORDER BY billing_period_start DESC
             LIMIT 1",
        )
        .bind(sub_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?
    } else {
        None
    };

    sqlx::query(
        "UPDATE subscriptions SET
         tier = $1,
         billing_period = 'monthly',
         current_period_start = $5,
         current_period_end = $5,
         next_billing_at = TIMESTAMPTZ '9999-12-31 23:59:59+00',
         max_vcpus = $2,
         max_apps = $3,
         price_cents_per_cycle = $4,
         extra_vcpu_blocks = 0,
         extra_app_blocks = 0,
         extra_block_price_cents_per_cycle = 0,
         updated_at = NOW()
        WHERE id = $6",
    )
    .bind(&req.tier_id)
    .bind(LEGACY_MAX_VCPUS_PLACEHOLDER)
    .bind(new_tier.enclaves)
    .bind(new_price)
    .bind(now)
    .bind(sub_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let (carried_invoice_id, carried_status) = current_ledger
        .as_ref()
        .map(|(_, invoice_id, status)| (*invoice_id, status.clone()))
        .or(latest_ledger_metadata)
        .unwrap_or((None, "credits_covered".to_string()));

    if let Some((current_segment_start, _, _)) = current_ledger {
        sqlx::query(
            "UPDATE subscription_ledger
             SET billing_period_end = $1
             WHERE subscription_id = $2 AND billing_period_start = $3",
        )
        .bind(now)
        .bind(sub_id)
        .bind(current_segment_start)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
    }

    sqlx::query(
        "INSERT INTO subscription_ledger
         (subscription_id, organization_id, billing_period_start, billing_period_end, tier, cost_hourly, invoice_id, status)
         VALUES ($1, $2, $3, NULL, $4, $5, $6, $7)
         ON CONFLICT (subscription_id, billing_period_start)
         DO UPDATE SET
             billing_period_end = EXCLUDED.billing_period_end,
             tier = EXCLUDED.tier,
             cost_hourly = EXCLUDED.cost_hourly,
             invoice_id = EXCLUDED.invoice_id,
             status = EXCLUDED.status"
    )
    .bind(sub_id)
    .bind(org_id)
    .bind(now)
    .bind(&req.tier_id)
    .bind(new_cost_hourly)
    .bind(carried_invoice_id)
    .bind(carried_status)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to roll subscription ledger: {}", e),
        )
    })?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit: {}", e),
        )
    })?;

    tracing::info!(
        "Subscription {} tier changed {} → {}",
        sub_id,
        old_tier_id,
        req.tier_id,
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "new_tier": req.tier_id,
        "new_price_cents_per_cycle": new_price,
        "effective": "immediate",
    })))
}

pub async fn cancel_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    require_billing_manager(&state, auth.user_id, org_id).await?;

    let sub: Option<(Uuid, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, billing_source, paddle_subscription_id, cancel_at_period_end
         FROM subscriptions
         WHERE organization_id = $1 AND status <> 'canceled'
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to read subscription".to_string(),
        )
    })?;

    let Some((sub_id, billing_source, paddle_subscription_id, cancel_at_period_end)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };
    if cancel_at_period_end {
        return Ok(Json(serde_json::json!({
            "success": true,
            "status": "canceling",
        })));
    }
    if billing_source == "enterprise" {
        return Err((
            StatusCode::CONFLICT,
            "Enterprise entitlements must be changed by an operator".to_string(),
        ));
    }
    if billing_source == "paddle" {
        let paddle_subscription_id = paddle_subscription_id
            .filter(|id| id.starts_with("sub_"))
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Paddle subscription mapping is invalid".to_string(),
                )
            })?;
        sqlx::query(
            "UPDATE subscription_intents SET status = 'canceled', updated_at = NOW()
             WHERE organization_id = $1 AND status = 'pending'
               AND expires_at <= NOW()",
        )
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to expire stale subscription changes".to_string(),
            )
        })?;
        let intent_id: Uuid = sqlx::query_scalar(
            "INSERT INTO subscription_intents
             (organization_id, requested_by_user_id, operation, subscription_id,
              paddle_subscription_id)
             VALUES ($1, $2, 'cancel', $3, $4) RETURNING id",
        )
        .bind(org_id)
        .bind(auth.user_id)
        .bind(sub_id)
        .bind(&paddle_subscription_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::CONFLICT,
                "Another subscription change is already pending".to_string(),
            )
        })?;
        let mut pending_tx = state.db.begin().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist pending cancellation".to_string(),
            )
        })?;
        let claimed = sqlx::query(
            "UPDATE subscription_intents SET status = 'provider_pending', updated_at = NOW()
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(intent_id)
        .execute(&mut *pending_tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist pending cancellation".to_string(),
            )
        })?
        .rows_affected();
        if claimed != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Cancellation is no longer pending".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE subscriptions SET cancel_at_period_end = true, updated_at = NOW() WHERE id = $1",
        )
        .bind(sub_id)
        .execute(&mut *pending_tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist pending cancellation".to_string(),
            )
        })?;
        pending_tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist pending cancellation".to_string(),
            )
        })?;

        let path = format!("/subscriptions/{paddle_subscription_id}/cancel");
        let body = serde_json::json!({"effective_from": "next_billing_period"});
        if let Err(error) = paddle_json_request(
            &state,
            reqwest::Method::POST,
            &path,
            Some(&body),
            Some(intent_id),
        )
        .await
        {
            // Cancellation may have reached Paddle despite a transport error.
            // Keep provider-pending state until a webhook reconciles the source
            // of truth rather than allowing a conflicting follow-up operation.
            return Err(error);
        }
        return Ok(Json(serde_json::json!({
            "success": true,
            "intent_id": intent_id,
            "status": "canceling",
        })));
    }

    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    close_open_subscription_segment(&mut tx, sub_id, now).await?;

    sqlx::query(
        "UPDATE subscriptions SET
         status = 'canceled',
         canceled_at = NOW(),
         cancel_at_period_end = false,
         current_period_end = $1,
         next_billing_at = TIMESTAMPTZ '9999-12-31 23:59:59+00',
         updated_at = NOW()
         WHERE id = $2",
    )
    .bind(now)
    .bind(sub_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit: {}", e),
        )
    })?;

    tracing::info!("Subscription {} canceled immediately", sub_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "status": "canceled",
    })))
}

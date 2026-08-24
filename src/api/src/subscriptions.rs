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
        let definitive_rejection = status.is_client_error()
            && !matches!(
                status,
                reqwest::StatusCode::REQUEST_TIMEOUT
                    | reqwest::StatusCode::CONFLICT
                    | reqwest::StatusCode::TOO_MANY_REQUESTS
            );
        return Err(if status == reqwest::StatusCode::NOT_FOUND {
            (
                StatusCode::GONE,
                "Paddle subscription no longer exists".to_string(),
            )
        } else if definitive_rejection {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Paddle rejected the request with status {status}"),
            )
        } else {
            (
                StatusCode::BAD_GATEWAY,
                format!("Paddle request failed with status {status}"),
            )
        });
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

    let plan = sqlx::query(
        "SELECT p.id, p.tier, p.enclave_limit, p.source, p.expires_at,
                p.terminated_at, p.created_at, p.updated_at,
                (SELECT COUNT(*) FROM compute_resources cr
                 JOIN cloud_credentials cc ON cc.resource_id = cr.id
                 WHERE cr.organization_id = p.organization_id
                   AND cc.managed_on_prem = true
                   AND cr.destroyed_at IS NULL
                   AND cr.state NOT IN ('terminated', 'failed')) AS allocated_enclaves
         FROM self_managed_plans p
         WHERE p.organization_id = $1",
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

    let Some(plan) = plan else {
        return Ok(Json(serde_json::json!({ "subscription": null })));
    };

    let subscription = sqlx::query(
        "SELECT s.id, s.user_id, s.tier, s.price_cents_per_cycle, s.status,
                s.pending_tier, s.pending_max_apps, s.catalog_valid,
                s.started_at, s.current_period_start, s.current_period_end,
                s.canceled_at, s.cancel_at_period_end, s.last_billed_at,
                s.next_billing_at, s.created_at, s.updated_at
         FROM subscriptions s
         WHERE s.organization_id = $1 AND s.self_managed_plan_id = $2
           AND s.status <> 'canceled'
         LIMIT 1",
    )
    .bind(org_id)
    .bind(plan.get::<Uuid, _>("id"))
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let source: String = plan.get("source");
    let tier: String = plan.get("tier");
    let enclave_limit: Option<i32> = plan.get("enclave_limit");
    let expires_at: Option<DateTime<Utc>> = plan.get("expires_at");
    let terminated_at: Option<DateTime<Utc>> = plan.get("terminated_at");
    let expired = expires_at.is_some_and(|value| value <= Utc::now());
    let status = if terminated_at.is_some() || enclave_limit == Some(0) {
        "terminated"
    } else if expired {
        "expired"
    } else {
        "active"
    };
    let unlimited = enclave_limit.is_none();
    let allocated_enclaves = plan.get::<i64, _>("allocated_enclaves");

    let (
        subscription_id,
        user_id,
        pending_tier,
        pending_limit,
        monthly_price,
        catalog_valid,
        started_at,
        period_start,
        period_end,
        canceled_at,
        cancel_at_period_end,
        last_billed_at,
        next_billing_at,
        created_at,
        updated_at,
    ) = if let Some(row) = subscription {
        let pending_tier: Option<String> = row.get("pending_tier");
        let pending_limit: Option<i32> = row.get("pending_max_apps");
        (
            Some(row.get::<Uuid, _>("id")),
            row.get::<Uuid, _>("user_id"),
            pending_tier,
            pending_limit,
            Some(row.get::<i64, _>("price_cents_per_cycle")),
            row.get::<bool, _>("catalog_valid"),
            Some(row.get::<DateTime<Utc>, _>("started_at")),
            Some(row.get::<DateTime<Utc>, _>("current_period_start")),
            Some(row.get::<DateTime<Utc>, _>("current_period_end")),
            row.get::<Option<DateTime<Utc>>, _>("canceled_at"),
            row.get::<bool, _>("cancel_at_period_end"),
            row.get::<Option<DateTime<Utc>>, _>("last_billed_at"),
            Some(row.get::<DateTime<Utc>, _>("next_billing_at")),
            row.get::<DateTime<Utc>, _>("created_at"),
            row.get::<DateTime<Utc>, _>("updated_at"),
        )
    } else {
        (
            None,
            auth.user_id,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            plan.get::<DateTime<Utc>, _>("created_at"),
            plan.get::<DateTime<Utc>, _>("updated_at"),
        )
    };

    Ok(Json(serde_json::json!({
        "subscription": {
            "id": subscription_id,
            "self_managed_plan_id": plan.get::<Uuid, _>("id"),
            "user_id": user_id,
            "organization_id": org_id,
            "source": &source,
            "tier": &tier,
            "tier_id": &tier,
            "tier_name": if source == "manual" { "Enterprise contract" } else { tier.as_str() },
            "billing_period": if source == "manual" { "contract" } else { "monthly" },
            "enclaves": enclave_limit,
            "max_apps": enclave_limit,
            "enclave_limit": enclave_limit,
            "unlimited_enclaves": unlimited,
            "allocated_enclaves": allocated_enclaves,
            "pending_enclave_limit": pending_limit,
            "pending_change": pending_tier.map(|tier_id| serde_json::json!({
                "tier_id": tier_id,
                "enclave_limit": pending_limit,
            })),
            "price_cents_per_cycle": monthly_price,
            "monthly_price_cents": monthly_price,
            "total_price_cents_per_cycle": monthly_price,
            "status": status,
            "catalog_valid": catalog_valid,
            "enterprise_expires_at": expires_at,
            "enterprise_entitlement_active": source == "manual" && status == "active",
            "started_at": started_at,
            "current_period_start": period_start,
            "current_period_end": period_end,
            "canceled_at": canceled_at,
            "cancel_at_period_end": cancel_at_period_end,
            "last_billed_at": last_billed_at,
            "next_billing_at": next_billing_at,
            "created_at": created_at,
            "updated_at": updated_at,
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
        "SELECT
             EXISTS(SELECT 1 FROM subscriptions WHERE organization_id = $1 AND status <> 'canceled')
             OR EXISTS(
                 SELECT 1 FROM self_managed_plans
                 WHERE organization_id = $1 AND source = 'manual'
                   AND (enclave_limit IS NULL OR enclave_limit > 0)
                   AND (expires_at IS NULL OR expires_at > NOW())
             )
             OR EXISTS(
                 SELECT 1 FROM self_managed_termination_jobs
                 WHERE organization_id = $1 AND status <> 'completed'
             )",
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

async fn finalize_paddle_tier_change(
    state: &AppState,
    organization_id: Uuid,
    subscription_id: Uuid,
    paddle_subscription_id: &str,
    intent_id: Uuid,
    new_tier_id: &str,
    new_limit: i32,
    price_id: &str,
    monthly_cents: i64,
    provider_status: Option<&str>,
    accepted: bool,
) -> Result<(), (StatusCode, String)> {
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to reconcile Paddle change".to_string(),
        )
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    let authoritative: Option<(Uuid, String, i32)> = sqlx::query_as(
        "SELECT p.id, s.status, s.max_apps
         FROM subscriptions s
         JOIN self_managed_plans p
           ON p.id = s.self_managed_plan_id AND p.organization_id = s.organization_id
         WHERE s.id = $1 AND s.organization_id = $2
           AND s.paddle_subscription_id = $3
           AND s.billing_source = 'paddle' AND s.status <> 'canceled'
           AND p.source = 'paddle'
         FOR UPDATE OF s, p",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(paddle_subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to verify subscription authority".to_string(),
        )
    })?;

    let intent_status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM subscription_intents
         WHERE id = $1 AND organization_id = $2 AND subscription_id = $3
           AND operation IN ('upgrade', 'downgrade')
           AND new_tier = $4 AND new_limit = $5
           AND provider_price_id = $6 AND provider_price_cents_per_cycle = $7
           AND paddle_subscription_id = $8
           AND status IN ('provider_pending', 'applied', 'canceled')
         FOR UPDATE",
    )
    .bind(intent_id)
    .bind(organization_id)
    .bind(subscription_id)
    .bind(new_tier_id)
    .bind(new_limit)
    .bind(price_id)
    .bind(monthly_cents)
    .bind(paddle_subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to lock Paddle change intent".to_string(),
        )
    })?;
    match intent_status.as_deref() {
        Some("provider_pending") => {}
        Some("applied" | "canceled") => {
            tx.commit().await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to reconcile Paddle change".to_string(),
                )
            })?;
            return Ok(());
        }
        _ => {
            return Err((
                StatusCode::CONFLICT,
                "Paddle change intent no longer owns the pending transition".to_string(),
            ));
        }
    }
    let Some((plan_id, current_status, current_limit)) = authoritative else {
        sqlx::query(
            "UPDATE subscription_intents
             SET status = 'canceled', updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND status = 'provider_pending'",
        )
        .bind(intent_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to close stale Paddle intent".to_string(),
            )
        })?;
        tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to close stale Paddle intent".to_string(),
            )
        })?;
        return Ok(());
    };

    if accepted {
        let status = provider_status
            .filter(|value| matches!(*value, "active" | "trialing" | "paused" | "past_due"))
            .unwrap_or(&current_status);
        let effective_limit = if matches!(status, "active" | "trialing") {
            new_limit
        } else {
            0
        };
        let updated_subscription = sqlx::query(
            "UPDATE subscriptions
             SET tier = $1, max_apps = $2, price_cents_per_cycle = $3,
                 paddle_price_id = $4, status = $5,
                 pending_tier = NULL, pending_max_apps = NULL,
                 provider_occurred_at = GREATEST(provider_occurred_at, NOW()),
                 updated_at = NOW()
             WHERE id = $6 AND organization_id = $7
               AND billing_source = 'paddle' AND self_managed_plan_id = $8",
        )
        .bind(new_tier_id)
        .bind(new_limit)
        .bind(monthly_cents)
        .bind(price_id)
        .bind(status)
        .bind(subscription_id)
        .bind(organization_id)
        .bind(plan_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to apply Paddle change".to_string(),
            )
        })?
        .rows_affected();
        if updated_subscription != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle subscription authority changed during finalization".to_string(),
            ));
        }
        let updated_plan = sqlx::query(
            "UPDATE self_managed_plans
             SET tier = $1, enclave_limit = $2, terminated_at = NULL, updated_at = NOW()
             WHERE id = $3 AND organization_id = $4 AND source = 'paddle'",
        )
        .bind(new_tier_id)
        .bind(effective_limit)
        .bind(plan_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to apply Paddle capacity".to_string(),
            )
        })?
        .rows_affected();
        if updated_plan != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle plan authority changed during finalization".to_string(),
            ));
        }
        let applied_intent = sqlx::query(
            "UPDATE subscription_intents
             SET status = 'applied', applied_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND status = 'provider_pending'",
        )
        .bind(intent_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to apply Paddle intent".to_string(),
            )
        })?
        .rows_affected();
        if applied_intent != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle change intent lost ownership during finalization".to_string(),
            ));
        }
    } else {
        let restored_limit = if matches!(current_status.as_str(), "active" | "trialing") {
            current_limit
        } else {
            0
        };
        let rolled_back_subscription = sqlx::query(
            "UPDATE subscriptions
             SET pending_tier = NULL, pending_max_apps = NULL, updated_at = NOW()
             WHERE id = $1 AND organization_id = $2
               AND pending_tier = $3 AND pending_max_apps = $4",
        )
        .bind(subscription_id)
        .bind(organization_id)
        .bind(new_tier_id)
        .bind(new_limit)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to roll back Paddle change".to_string(),
            )
        })?
        .rows_affected();
        if rolled_back_subscription != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle pending projection changed during rollback".to_string(),
            ));
        }
        let restored_plan = sqlx::query(
            "UPDATE self_managed_plans
             SET enclave_limit = $1, updated_at = NOW()
             WHERE id = $2 AND organization_id = $3 AND source = 'paddle'",
        )
        .bind(restored_limit)
        .bind(plan_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to restore Paddle capacity".to_string(),
            )
        })?
        .rows_affected();
        if restored_plan != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle plan authority changed during rollback".to_string(),
            ));
        }
        let canceled_intent = sqlx::query(
            "UPDATE subscription_intents
             SET status = 'canceled', updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND status = 'provider_pending'",
        )
        .bind(intent_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to close rejected Paddle intent".to_string(),
            )
        })?
        .rows_affected();
        if canceled_intent != 1 {
            return Err((
                StatusCode::CONFLICT,
                "Paddle change intent lost ownership during rollback".to_string(),
            ));
        }
    }
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to reconcile Paddle change".to_string(),
        )
    })?;
    Ok(())
}

async fn submit_paddle_tier_change(
    state: &AppState,
    organization_id: Uuid,
    subscription_id: Uuid,
    paddle_subscription_id: &str,
    intent_id: Uuid,
    new_tier_id: &str,
    new_limit: i32,
    price_id: &str,
    monthly_cents: i64,
    proration_mode: &str,
    reconcile_first: bool,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    fn confirms_price(response: &serde_json::Value, expected_price_id: &str) -> bool {
        response["data"]["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["price"]["id"].as_str() == Some(expected_price_id)
                    || item["price_id"].as_str() == Some(expected_price_id)
            })
        })
    }

    let path = format!("/subscriptions/{paddle_subscription_id}");
    if reconcile_first {
        match paddle_json_request(state, reqwest::Method::GET, &path, None, None).await {
            Ok(provider) if provider["data"]["status"] == "canceled" => {
                apply_confirmed_paddle_cancellation(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                )
                .await?;
                finalize_paddle_tier_change(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                    new_tier_id,
                    new_limit,
                    price_id,
                    monthly_cents,
                    None,
                    false,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "status": "canceled",
                    "effective": "provider_reconciled",
                })));
            }
            Ok(provider) if confirms_price(&provider, price_id) => {
                finalize_paddle_tier_change(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                    new_tier_id,
                    new_limit,
                    price_id,
                    monthly_cents,
                    provider["data"]["status"].as_str(),
                    true,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "new_tier": new_tier_id,
                    "new_price_cents_per_cycle": monthly_cents,
                    "effective": "provider_reconciled",
                })));
            }
            Ok(_) => {}
            Err(error) if error.0 == StatusCode::GONE => {
                apply_confirmed_paddle_cancellation(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                )
                .await?;
                finalize_paddle_tier_change(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                    new_tier_id,
                    new_limit,
                    price_id,
                    monthly_cents,
                    None,
                    false,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "status": "canceled",
                    "effective": "provider_reconciled",
                })));
            }
            Err(error) => return Err(error),
        }
    }

    let body = serde_json::json!({
        "items": [{"price_id": price_id, "quantity": 1}],
        "proration_billing_mode": proration_mode,
        "on_payment_failure": "prevent_change",
        "custom_data": {
            "caution_operation": "byoc_subscription",
            "caution_change_intent_id": intent_id.to_string(),
            "caution_organization_id": organization_id.to_string(),
            "caution_tier_id": new_tier_id,
        },
    });
    let response = match paddle_json_request(
        state,
        reqwest::Method::PATCH,
        &path,
        Some(&body),
        Some(intent_id),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            if error.0 == StatusCode::GONE {
                apply_confirmed_paddle_cancellation(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                )
                .await?;
                finalize_paddle_tier_change(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                    new_tier_id,
                    new_limit,
                    price_id,
                    monthly_cents,
                    None,
                    false,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "status": "canceled",
                    "effective": "provider_confirmed",
                })));
            } else if error.0 == StatusCode::UNPROCESSABLE_ENTITY {
                finalize_paddle_tier_change(
                    state,
                    organization_id,
                    subscription_id,
                    paddle_subscription_id,
                    intent_id,
                    new_tier_id,
                    new_limit,
                    price_id,
                    monthly_cents,
                    None,
                    false,
                )
                .await?;
            }
            return Err(error);
        }
    };
    if response["data"]["status"] == "canceled" {
        apply_confirmed_paddle_cancellation(
            state,
            organization_id,
            subscription_id,
            paddle_subscription_id,
            intent_id,
        )
        .await?;
        finalize_paddle_tier_change(
            state,
            organization_id,
            subscription_id,
            paddle_subscription_id,
            intent_id,
            new_tier_id,
            new_limit,
            price_id,
            monthly_cents,
            None,
            false,
        )
        .await?;
        return Ok(Json(serde_json::json!({
            "success": true,
            "intent_id": intent_id,
            "status": "canceled",
            "effective": "provider_confirmed",
        })));
    }
    if !confirms_price(&response, price_id) {
        return Ok(Json(serde_json::json!({
            "success": true,
            "intent_id": intent_id,
            "new_tier": new_tier_id,
            "new_price_cents_per_cycle": monthly_cents,
            "effective": "pending_provider_reconciliation",
        })));
    }
    finalize_paddle_tier_change(
        state,
        organization_id,
        subscription_id,
        paddle_subscription_id,
        intent_id,
        new_tier_id,
        new_limit,
        price_id,
        monthly_cents,
        response["data"]["status"].as_str(),
        true,
    )
    .await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "intent_id": intent_id,
        "new_tier": new_tier_id,
        "new_price_cents_per_cycle": monthly_cents,
        "effective": "provider_confirmed",
    })))
}

async fn change_paddle_subscription(
    state: &AppState,
    auth: &AuthContext,
    organization_id: Uuid,
    subscription_id: Uuid,
    paddle_subscription_id: &str,
    new_tier_id: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_billing_manager(state, auth.user_id, organization_id).await?;
    let configured_tier = state.pricing.subscription_tiers.get(new_tier_id);
    let mut pending_tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *pending_tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    let conflicting_manual_change: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM self_managed_plan_changes
             WHERE organization_id = $1 AND status IN ('pending', 'provider_pending')
         )",
    )
    .bind(organization_id)
    .fetch_one(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to inspect pending plan authority".to_string(),
        )
    })?;
    if conflicting_manual_change {
        return Err((
            StatusCode::CONFLICT,
            "An operator plan transition is already pending".to_string(),
        ));
    }
    let authoritative: Option<(Uuid, i32, String)> = sqlx::query_as(
        "SELECT p.id, s.max_apps, s.tier
         FROM subscriptions s
         JOIN self_managed_plans p
           ON p.id = s.self_managed_plan_id AND p.organization_id = s.organization_id
         WHERE s.id = $1 AND s.organization_id = $2
           AND s.paddle_subscription_id = $3 AND s.billing_source = 'paddle'
           AND s.status <> 'canceled' AND p.source = 'paddle'
         FOR UPDATE OF s, p",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(paddle_subscription_id)
    .fetch_optional(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to verify subscription authority".to_string(),
        )
    })?;
    let Some((_plan_id, old_limit, current_tier)) = authoritative else {
        return Err((
            StatusCode::CONFLICT,
            "Paddle subscription no longer controls this plan".to_string(),
        ));
    };
    if current_tier == new_tier_id {
        return Err((StatusCode::BAD_REQUEST, "Already on this tier".to_string()));
    }
    let existing_intent: Option<(
        Uuid,
        Option<String>,
        Option<i32>,
        Option<i32>,
        Option<String>,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, new_tier, old_limit, new_limit, provider_price_id,
                provider_price_cents_per_cycle, provider_proration_mode
         FROM subscription_intents
         WHERE organization_id = $1 AND subscription_id = $2
           AND operation IN ('upgrade', 'downgrade') AND status = 'provider_pending'
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(subscription_id)
    .fetch_optional(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to inspect pending Paddle change".to_string(),
        )
    })?;
    if let Some((
        intent_id,
        existing_tier,
        _recorded_old_limit,
        recorded_new_limit,
        recorded_price_id,
        recorded_monthly_cents,
        recorded_proration_mode,
    )) = existing_intent
    {
        if existing_tier.as_deref() != Some(new_tier_id) {
            return Err((
                StatusCode::CONFLICT,
                "A different Paddle tier change is already pending".to_string(),
            ));
        }
        let (
            Some(recorded_new_limit),
            Some(recorded_price_id),
            Some(recorded_monthly_cents),
            Some(recorded_proration_mode),
        ) = (
            recorded_new_limit,
            recorded_price_id,
            recorded_monthly_cents,
            recorded_proration_mode,
        )
        else {
            return Err((
                StatusCode::CONFLICT,
                "Pending Paddle change lacks a durable provider payload".to_string(),
            ));
        };
        pending_tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to resume pending Paddle change".to_string(),
            )
        })?;
        return submit_paddle_tier_change(
            state,
            organization_id,
            subscription_id,
            paddle_subscription_id,
            intent_id,
            new_tier_id,
            recorded_new_limit,
            &recorded_price_id,
            recorded_monthly_cents,
            &recorded_proration_mode,
            true,
        )
        .await;
    }
    let new_tier =
        configured_tier.ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;
    let price_id = new_tier.paddle_price_id.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Selected tier is not available in Paddle".to_string(),
        )
    })?;
    if new_tier.enclaves < old_limit {
        let allocated: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc
               ON cc.resource_id = cr.id AND cc.organization_id = cr.organization_id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.destroyed_at IS NULL
               AND cr.state NOT IN ('terminated', 'failed')",
        )
        .bind(organization_id)
        .fetch_one(&mut *pending_tx)
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
    .execute(&mut *pending_tx)
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
    let proration_mode = if new_tier.enclaves > old_limit {
        "prorated_immediately"
    } else {
        "do_not_bill"
    };
    let monthly_cents = new_tier.monthly_cents();
    let intent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO subscription_intents
         (organization_id, requested_by_user_id, operation, subscription_id,
          paddle_subscription_id, old_limit, new_tier, new_limit, status,
          provider_price_id, provider_price_cents_per_cycle, provider_proration_mode)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'provider_pending', $9, $10, $11)
         RETURNING id",
    )
    .bind(organization_id)
    .bind(auth.user_id)
    .bind(operation)
    .bind(subscription_id)
    .bind(paddle_subscription_id)
    .bind(old_limit)
    .bind(new_tier_id)
    .bind(new_tier.enclaves)
    .bind(price_id)
    .bind(monthly_cents)
    .bind(proration_mode)
    .fetch_one(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Another subscription change is already pending".to_string(),
        )
    })?;

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
    sqlx::query(
        "UPDATE self_managed_plans p
         SET enclave_limit = CASE
             WHEN p.enclave_limit IS NULL THEN $1
             ELSE LEAST(p.enclave_limit, $1)
         END, updated_at = NOW()
         FROM subscriptions s
         WHERE s.id = $2 AND s.self_managed_plan_id = p.id
           AND p.source = 'paddle' AND $1 < $3",
    )
    .bind(new_tier.enclaves)
    .bind(subscription_id)
    .bind(old_limit)
    .execute(&mut *pending_tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to reserve downgraded plan capacity".to_string(),
        )
    })?;
    pending_tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to persist pending subscription change".to_string(),
        )
    })?;

    submit_paddle_tier_change(
        state,
        organization_id,
        subscription_id,
        paddle_subscription_id,
        intent_id,
        new_tier_id,
        new_tier.enclaves,
        price_id,
        monthly_cents,
        proration_mode,
        false,
    )
    .await
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    let existing_locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscriptions
         WHERE organization_id = $1 AND status <> 'canceled'
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;
    if existing_locked.is_some() {
        return Err((
            StatusCode::CONFLICT,
            "Organization already has an active subscription".to_string(),
        ));
    }

    let plan_id: Uuid = sqlx::query_scalar(
        "INSERT INTO self_managed_plans
            (organization_id, tier, enclave_limit, source, terminated_at)
         VALUES ($1, $2, $3, 'legacy', NULL)
         ON CONFLICT (organization_id) DO UPDATE SET
            tier = EXCLUDED.tier, enclave_limit = EXCLUDED.enclave_limit,
            terminated_at = NULL, updated_at = NOW()
         WHERE self_managed_plans.source = 'legacy'
         RETURNING id",
    )
    .bind(org_id)
    .bind(&req.tier_id)
    .bind(tier.enclaves)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create self-managed plan: {}", e),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            "Organization already has a provider or operator-managed plan".to_string(),
        )
    })?;

    let sub_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO subscriptions (
             user_id, organization_id, tier, billing_period, max_vcpus, max_apps,
             price_cents_per_cycle, extra_vcpu_blocks, extra_app_blocks,
             extra_block_price_cents_per_cycle, current_period_end, next_billing_at,
             self_managed_plan_id
         )
         VALUES ($1, $2, $3, 'monthly', $4, $5, $6, 0, 0, 0, $7,
                 TIMESTAMPTZ '9999-12-31 23:59:59+00', $8)
         RETURNING id",
    )
    .bind(auth.user_id)
    .bind(org_id)
    .bind(&req.tier_id)
    .bind(LEGACY_MAX_VCPUS_PLACEHOLDER)
    .bind(tier.enclaves)
    .bind(price_per_cycle)
    .bind(now)
    .bind(plan_id)
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
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    require_billing_manager(&state, auth.user_id, org_id).await?;

    let sub: Option<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, tier, billing_source, paddle_subscription_id
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

    let Some((sub_id, old_tier_id, billing_source, paddle_subscription_id)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    if old_tier_id == req.tier_id && billing_source != "paddle" {
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
            &req.tier_id,
        )
        .await;
    }

    let new_tier = state
        .pricing
        .subscription_tiers
        .get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to lock subscription authority: {}", e),
            )
        })?;
    let locked_plan_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT self_managed_plan_id FROM subscriptions
         WHERE id = $1 AND organization_id = $2
           AND billing_source = 'legacy_credits' AND status <> 'canceled'
           AND self_managed_plan_id IS NOT NULL
         FOR UPDATE",
    )
    .bind(sub_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to revalidate subscription authority: {}", e),
        )
    })?;
    let Some(locked_plan_id) = locked_plan_id else {
        return Err((
            StatusCode::CONFLICT,
            "Subscription authority changed; retry from current state".to_string(),
        ));
    };
    let locked_plan: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM self_managed_plans
         WHERE id = $1 AND organization_id = $2 AND source = 'legacy'
         FOR UPDATE",
    )
    .bind(locked_plan_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to revalidate plan authority: {}", e),
        )
    })?;
    if locked_plan.is_none() {
        return Err((
            StatusCode::CONFLICT,
            "Subscription no longer controls this plan".to_string(),
        ));
    }

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

    let updated_subscription = sqlx::query(
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
        WHERE id = $6 AND organization_id = $7
          AND billing_source = 'legacy_credits' AND status <> 'canceled'
          AND self_managed_plan_id = $8",
    )
    .bind(&req.tier_id)
    .bind(LEGACY_MAX_VCPUS_PLACEHOLDER)
    .bind(new_tier.enclaves)
    .bind(new_price)
    .bind(now)
    .bind(sub_id)
    .bind(org_id)
    .bind(locked_plan_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?
    .rows_affected();
    if updated_subscription != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Subscription authority changed; retry from current state".to_string(),
        ));
    }

    sqlx::query(
        "UPDATE self_managed_plans
         SET tier = $1, enclave_limit = $2, terminated_at = NULL, updated_at = NOW()
         WHERE id = $3 AND organization_id = $4 AND source = 'legacy'",
    )
    .bind(&req.tier_id)
    .bind(new_tier.enclaves)
    .bind(locked_plan_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update self-managed plan: {}", e),
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

async fn roll_back_rejected_paddle_cancellation(
    state: &AppState,
    organization_id: Uuid,
    subscription_id: Uuid,
    intent_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to roll back Paddle cancellation".to_string(),
        )
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    let authoritative: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscriptions
         WHERE id = $1 AND organization_id = $2 AND billing_source = 'paddle'
           AND status <> 'canceled'
         FOR UPDATE",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to lock Paddle subscription".to_string(),
        )
    })?;
    let claimed_intent: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscription_intents
         WHERE id = $1 AND organization_id = $2 AND subscription_id = $3
           AND operation = 'cancel' AND status = 'provider_pending'
         FOR UPDATE",
    )
    .bind(intent_id)
    .bind(organization_id)
    .bind(subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to lock rejected cancellation intent".to_string(),
        )
    })?;
    if authoritative.is_none() || claimed_intent.is_none() {
        tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to roll back Paddle cancellation".to_string(),
            )
        })?;
        return Ok(());
    }
    let restored = sqlx::query(
        "UPDATE subscriptions SET cancel_at_period_end = false, updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND billing_source = 'paddle'
           AND status <> 'canceled' AND cancel_at_period_end = true",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to restore Paddle subscription".to_string(),
        )
    })?
    .rows_affected();
    if restored != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Paddle cancellation projection changed during rollback".to_string(),
        ));
    }
    let canceled_intent = sqlx::query(
        "UPDATE subscription_intents SET status = 'canceled', updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND subscription_id = $3
           AND operation = 'cancel' AND status = 'provider_pending'",
    )
    .bind(intent_id)
    .bind(organization_id)
    .bind(subscription_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to close rejected cancellation intent".to_string(),
        )
    })?
    .rows_affected();
    if canceled_intent != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Paddle cancellation intent changed during rollback".to_string(),
        ));
    }
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to roll back Paddle cancellation".to_string(),
        )
    })?;
    Ok(())
}

async fn apply_confirmed_paddle_cancellation(
    state: &AppState,
    organization_id: Uuid,
    subscription_id: Uuid,
    paddle_subscription_id: &str,
    intent_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to reconcile Paddle cancellation".to_string(),
        )
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    let plan_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT self_managed_plan_id FROM subscriptions
         WHERE id = $1 AND organization_id = $2
           AND paddle_subscription_id = $3 AND billing_source = 'paddle'
           AND status <> 'canceled' AND self_managed_plan_id IS NOT NULL
         FOR UPDATE",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(paddle_subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to verify subscription authority".to_string(),
        )
    })?;
    let Some(plan_id) = plan_id else {
        sqlx::query(
            "UPDATE subscription_intents SET status = 'applied',
                    applied_at = COALESCE(applied_at, NOW()), updated_at = NOW()
             WHERE id = $1 AND organization_id = $2
               AND operation = 'cancel' AND status IN ('provider_pending', 'applied')",
        )
        .bind(intent_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to reconcile cancellation intent".to_string(),
            )
        })?;
        tx.commit().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to reconcile Paddle cancellation".to_string(),
            )
        })?;
        return Ok(());
    };
    let locked_plan: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM self_managed_plans
         WHERE id = $1 AND organization_id = $2 AND source = 'paddle'
         FOR UPDATE",
    )
    .bind(plan_id)
    .bind(organization_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to verify plan authority".to_string(),
        )
    })?;
    if locked_plan.is_none() {
        return Err((
            StatusCode::CONFLICT,
            "Paddle subscription no longer controls this plan".to_string(),
        ));
    }

    sqlx::query(
        "UPDATE subscriptions
         SET status = 'canceled', canceled_at = COALESCE(canceled_at, $1),
             cancel_at_period_end = false,
             provider_occurred_at = GREATEST(provider_occurred_at, $1), updated_at = NOW()
         WHERE id = $2 AND organization_id = $3
           AND paddle_subscription_id = $4 AND billing_source = 'paddle'
           AND self_managed_plan_id = $5",
    )
    .bind(now)
    .bind(subscription_id)
    .bind(organization_id)
    .bind(paddle_subscription_id)
    .bind(plan_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to project Paddle cancellation".to_string(),
        )
    })?;

    let manual_change: Option<(Uuid, Option<i32>, Option<DateTime<Utc>>, String, String)> =
        sqlx::query_as(
            "SELECT id, requested_enclave_limit, requested_expires_at,
                    operator_identity, operator_reason
             FROM self_managed_plan_changes
             WHERE organization_id = $1 AND subscription_id = $2
               AND status = 'provider_pending'
             ORDER BY created_at LIMIT 1 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(subscription_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to inspect pending plan transition".to_string(),
            )
        })?;
    if let Some((change_id, limit, expires_at, operator, reason)) = manual_change {
        sqlx::query(
            "UPDATE self_managed_plans
             SET tier = 'enterprise_contract', enclave_limit = $1, source = 'manual',
                 expires_at = $2, operator_identity = $3, operator_reason = $4,
                 terminated_at = NULL, updated_at = NOW()
             WHERE id = $5 AND organization_id = $6 AND source = 'paddle'",
        )
        .bind(limit)
        .bind(expires_at)
        .bind(operator)
        .bind(reason)
        .bind(plan_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to apply manual plan transition".to_string(),
            )
        })?;
        sqlx::query(
            "UPDATE self_managed_plan_changes
             SET status = 'applied', applied_at = NOW(), updated_at = NOW()
             WHERE id = $1 AND status = 'provider_pending'",
        )
        .bind(change_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to apply manual transition intent".to_string(),
            )
        })?;
    } else {
        sqlx::query(
            "UPDATE self_managed_plans
             SET enclave_limit = 0, terminated_at = COALESCE(terminated_at, $1), updated_at = NOW()
             WHERE id = $2 AND organization_id = $3 AND source = 'paddle'",
        )
        .bind(now)
        .bind(plan_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to disable canceled Paddle plan".to_string(),
            )
        })?;
        sqlx::query(
            "INSERT INTO self_managed_termination_jobs
                (organization_id, self_managed_plan_id, subscription_id,
                 resource_id, provider_occurred_at)
             SELECT $1, $2, $3, cr.id, $4
             FROM compute_resources cr
             WHERE cr.organization_id = $1 AND cr.destroyed_at IS NULL
               AND EXISTS (
                   SELECT 1 FROM cloud_credentials cc
                   WHERE cc.resource_id = cr.id AND cc.organization_id = $1
                     AND cc.managed_on_prem = true
               )
             ON CONFLICT (subscription_id, resource_id) DO NOTHING",
        )
        .bind(organization_id)
        .bind(plan_id)
        .bind(subscription_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to queue canceled resources".to_string(),
            )
        })?;
    }
    sqlx::query(
        "UPDATE subscriptions SET self_managed_plan_id = NULL, updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND self_managed_plan_id = $3",
    )
    .bind(subscription_id)
    .bind(organization_id)
    .bind(plan_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to detach canceled Paddle history".to_string(),
        )
    })?;
    sqlx::query(
        "UPDATE subscription_intents SET status = 'applied',
                applied_at = COALESCE(applied_at, NOW()), updated_at = NOW()
         WHERE id = $1 AND organization_id = $2
           AND operation = 'cancel' AND status IN ('provider_pending', 'applied')",
    )
    .bind(intent_id)
    .bind(organization_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to apply cancellation intent".to_string(),
        )
    })?;
    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to reconcile Paddle cancellation".to_string(),
        )
    })?;
    Ok(())
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
    if cancel_at_period_end && billing_source != "paddle" {
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
        if cancel_at_period_end {
            let intent_id: Uuid = sqlx::query_scalar(
                "SELECT id FROM subscription_intents
                 WHERE organization_id = $1 AND subscription_id = $2
                   AND operation = 'cancel' AND status IN ('provider_pending', 'applied')
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(org_id)
            .bind(sub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to inspect pending cancellation".to_string(),
                )
            })?
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    "Cancellation state requires operator reconciliation".to_string(),
                )
            })?;
            let lookup_path = format!("/subscriptions/{paddle_subscription_id}");
            let provider =
                match paddle_json_request(&state, reqwest::Method::GET, &lookup_path, None, None)
                    .await
                {
                    Ok(provider) => provider,
                    Err(error) if error.0 == StatusCode::GONE => {
                        apply_confirmed_paddle_cancellation(
                            &state,
                            org_id,
                            sub_id,
                            &paddle_subscription_id,
                            intent_id,
                        )
                        .await?;
                        return Ok(Json(serde_json::json!({
                            "success": true,
                            "intent_id": intent_id,
                            "status": "canceled",
                        })));
                    }
                    Err(error) => return Err(error),
                };
            let provider_canceled = provider["data"]["status"] == "canceled";
            let provider_scheduled_cancel =
                provider["data"]["scheduled_change"]["action"] == "cancel";
            if provider_canceled {
                apply_confirmed_paddle_cancellation(
                    &state,
                    org_id,
                    sub_id,
                    &paddle_subscription_id,
                    intent_id,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "status": "canceled",
                })));
            }
            if !provider_scheduled_cancel {
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
                    if error.0 == StatusCode::GONE {
                        apply_confirmed_paddle_cancellation(
                            &state,
                            org_id,
                            sub_id,
                            &paddle_subscription_id,
                            intent_id,
                        )
                        .await?;
                        return Ok(Json(serde_json::json!({
                            "success": true,
                            "intent_id": intent_id,
                            "status": "canceled",
                        })));
                    }
                    if error.0 == StatusCode::UNPROCESSABLE_ENTITY {
                        roll_back_rejected_paddle_cancellation(&state, org_id, sub_id, intent_id)
                            .await?;
                    }
                    return Err(error);
                }
            }
            return Ok(Json(serde_json::json!({
                "success": true,
                "intent_id": intent_id,
                "status": "canceling",
            })));
        }
        let mut pending_tx = state.db.begin().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to persist pending cancellation".to_string(),
            )
        })?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(org_id.to_string())
            .execute(&mut *pending_tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to lock subscription authority".to_string(),
                )
            })?;
        let conflicting_manual_change: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM self_managed_plan_changes
                 WHERE organization_id = $1 AND status IN ('pending', 'provider_pending')
             )",
        )
        .bind(org_id)
        .fetch_one(&mut *pending_tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to inspect pending plan authority".to_string(),
            )
        })?;
        if conflicting_manual_change {
            return Err((
                StatusCode::CONFLICT,
                "An operator plan transition is already pending".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE subscription_intents SET status = 'canceled', updated_at = NOW()
             WHERE organization_id = $1 AND status = 'pending'
               AND expires_at <= NOW()",
        )
        .bind(org_id)
        .execute(&mut *pending_tx)
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
              paddle_subscription_id, status)
             SELECT $1, $2, 'cancel', s.id, $4, 'provider_pending'
             FROM subscriptions s
             JOIN self_managed_plans p
               ON p.id = s.self_managed_plan_id AND p.organization_id = s.organization_id
             WHERE s.id = $3 AND s.organization_id = $1
               AND s.paddle_subscription_id = $4 AND s.billing_source = 'paddle'
               AND s.status <> 'canceled' AND p.source = 'paddle'
             FOR UPDATE OF s, p
             RETURNING id",
        )
        .bind(org_id)
        .bind(auth.user_id)
        .bind(sub_id)
        .bind(&paddle_subscription_id)
        .fetch_optional(&mut *pending_tx)
        .await
        .map_err(|_| {
            (
                StatusCode::CONFLICT,
                "Another subscription change is already pending".to_string(),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                "Paddle subscription no longer controls this plan".to_string(),
            )
        })?;
        sqlx::query(
            "UPDATE subscriptions SET cancel_at_period_end = true, updated_at = NOW()
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(sub_id)
        .bind(org_id)
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
            if error.0 == StatusCode::GONE {
                apply_confirmed_paddle_cancellation(
                    &state,
                    org_id,
                    sub_id,
                    &paddle_subscription_id,
                    intent_id,
                )
                .await?;
                return Ok(Json(serde_json::json!({
                    "success": true,
                    "intent_id": intent_id,
                    "status": "canceled",
                })));
            }
            if error.0 == StatusCode::UNPROCESSABLE_ENTITY {
                roll_back_rejected_paddle_cancellation(&state, org_id, sub_id, intent_id).await?;
            }
            // Ambiguous transport/server failures retain provider-pending state
            // and the idempotency key so an exact retry can reconcile safely.
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to lock subscription authority".to_string(),
            )
        })?;
    // Match pre-plan rolling metering binaries, which lock the open ledger row
    // before the subscription row.
    sqlx::query(
        "SELECT sl.id
         FROM subscription_ledger sl
         JOIN subscriptions s ON s.id = sl.subscription_id
         WHERE sl.subscription_id = $1 AND s.organization_id = $2
           AND sl.billing_period_end IS NULL
         ORDER BY sl.id
         FOR UPDATE OF sl",
    )
    .bind(sub_id)
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;
    let legacy_plan_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT p.id
         FROM subscriptions s
         JOIN self_managed_plans p
           ON p.id = s.self_managed_plan_id AND p.organization_id = s.organization_id
         WHERE s.id = $1 AND s.organization_id = $2
           AND s.billing_source = 'legacy_credits' AND s.status <> 'canceled'
           AND p.source = 'legacy'
         FOR UPDATE OF s, p",
    )
    .bind(sub_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;
    let Some(legacy_plan_id) = legacy_plan_id else {
        return Err((
            StatusCode::CONFLICT,
            "Legacy subscription no longer controls this plan".to_string(),
        ));
    };

    close_open_subscription_segment(&mut tx, sub_id, now).await?;

    let canceled = sqlx::query(
        "UPDATE subscriptions SET
         status = 'canceled',
         canceled_at = NOW(),
         cancel_at_period_end = false,
         current_period_end = $1,
         next_billing_at = TIMESTAMPTZ '9999-12-31 23:59:59+00',
         updated_at = NOW()
         WHERE id = $2 AND organization_id = $3
           AND billing_source = 'legacy_credits' AND status <> 'canceled'
           AND self_managed_plan_id = $4",
    )
    .bind(now)
    .bind(sub_id)
    .bind(org_id)
    .bind(legacy_plan_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?
    .rows_affected();
    if canceled != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Legacy subscription authority changed during cancellation".to_string(),
        ));
    }

    let disabled = sqlx::query(
        "UPDATE self_managed_plans
         SET enclave_limit = 0, terminated_at = COALESCE(terminated_at, $1), updated_at = NOW()
         WHERE id = $2 AND organization_id = $3 AND source = 'legacy'",
    )
    .bind(now)
    .bind(legacy_plan_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to disable self-managed plan: {}", e),
        )
    })?
    .rows_affected();
    if disabled != 1 {
        return Err((
            StatusCode::CONFLICT,
            "Legacy plan authority changed during cancellation".to_string(),
        ));
    }

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

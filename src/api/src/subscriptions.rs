use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::{get_user_primary_org, AppState, AuthContext};

fn tier_display_name(id: &str) -> String {
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
    stored_max_vcpus: i32,
    stored_max_apps: i32,
    stored_price_cents: i64,
) -> (String, i32, i32, i64) {
    if let Some(tier) = pricing.subscription_tiers.get(tier_id) {
        (
            tier_display_name(tier_id),
            tier.vcpu,
            tier.enclaves,
            tier.monthly_price_cents(),
        )
    } else {
        (
            "Unknown".to_string(),
            stored_max_vcpus,
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
    tier_entries.sort_by_key(|(_, t)| t.annual_cents);

    let tiers: Vec<serde_json::Value> = tier_entries
        .iter()
        .map(|(id, t)| {
            serde_json::json!({
                "id": id,
                "name": tier_display_name(id),
                "enclaves": t.enclaves,
                "vcpu": t.vcpu,
                "ram_gb": t.ram_gb,
                "storage_gb": t.storage_gb,
                "price_cents_per_cycle": t.monthly_price_cents(),
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
        "SELECT id, user_id, organization_id, tier, max_vcpus, max_apps, price_cents_per_cycle, status,
                started_at, current_period_start, current_period_end, canceled_at, cancel_at_period_end,
                last_billed_at, next_billing_at, created_at, updated_at
         FROM subscriptions
         WHERE organization_id = $1 AND status IN ('active', 'past_due')
         LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some(row) = row else {
        return Ok(Json(serde_json::json!({ "subscription": null })));
    };

    let tier: String = row.get("tier");
    let (tier_name, max_vcpus, max_apps, price_cents_per_cycle) = resolved_subscription_values(
        &state.pricing,
        &tier,
        row.get("max_vcpus"),
        row.get("max_apps"),
        row.get("price_cents_per_cycle"),
    );

    Ok(Json(serde_json::json!({
        "subscription": {
            "id": row.get::<Uuid, _>("id"),
            "user_id": row.get::<Uuid, _>("user_id"),
            "organization_id": row.get::<Uuid, _>("organization_id"),
            "tier": tier,
            "tier_name": tier_name,
            "billing_period": "monthly",
            "max_vcpus": max_vcpus,
            "max_apps": max_apps,
            "price_cents_per_cycle": price_cents_per_cycle,
            "total_price_cents_per_cycle": price_cents_per_cycle,
            "status": row.get::<String, _>("status"),
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

pub async fn subscribe(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    let price_per_cycle = tier.monthly_price_cents();
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
    .bind(tier.vcpu)
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

    let sub: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, tier
         FROM subscriptions WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, old_tier_id)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    if old_tier_id == req.tier_id {
        return Err((StatusCode::BAD_REQUEST, "Already on this tier".to_string()));
    }

    let now = Utc::now();
    let new_price = new_tier.monthly_price_cents();
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
    .bind(new_tier.vcpu)
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

    let sub: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id
         FROM subscriptions
         WHERE organization_id = $1 AND status IN ('active', 'past_due')
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

    let Some((sub_id,)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

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

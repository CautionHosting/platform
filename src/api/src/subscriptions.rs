use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Datelike, Utc};
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, get_user_primary_org, BillingDiscounts};

pub fn calculate_cycle_price(annual_cents: i64, billing_period: &str, discounts: &BillingDiscounts) -> i64 {
    match billing_period {
        "yearly" => (annual_cents as f64 * (1.0 - discounts.yearly_percent_off / 100.0)) as i64,
        "2year"  => (annual_cents as f64 * 2.0 * (1.0 - discounts.two_year_percent_off / 100.0)) as i64,
        _        => annual_cents / 12,
    }
}

pub fn calculate_period_end(start: DateTime<Utc>, billing_period: &str) -> DateTime<Utc> {
    let add_months: i32 = match billing_period {
        "yearly" => 12,
        "2year"  => 24,
        _        => 1,
    };

    let total_months = start.month0() as i32 + add_months;
    let target_year = start.year() + total_months / 12;
    let target_month = (total_months % 12) as u32 + 1;
    let day = start.day().min(days_in_month(target_year, target_month));

    start.date_naive()
        .with_year(target_year).unwrap_or(start.date_naive())
        .with_month(target_month).unwrap_or(start.date_naive())
        .with_day(day).unwrap_or(start.date_naive())
        .and_time(start.time())
        .and_utc()
}

pub fn days_in_month(year: i32, month: u32) -> u32 {
    use chrono::NaiveDate;
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    NaiveDate::from_ymd_opt(ny, nm, 1)
        .unwrap_or_else(|| NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap())
        .pred_opt().unwrap_or(NaiveDate::from_ymd_opt(year, month, 28).unwrap())
        .day()
}

fn tier_display_name(id: &str) -> String {
    id.split('_').map(|w| {
        let mut c = w.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().to_string() + c.as_str(),
        }
    }).collect::<Vec<_>>().join(" ")
}

pub async fn get_subscription_tiers(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let discounts = &state.pricing.billing_discounts;
    let extra_block = &state.pricing.extra_block;

    let mut tier_entries: Vec<(&String, &crate::TierPricing)> = state.pricing.subscription_tiers.iter().collect();
    tier_entries.sort_by_key(|(_, t)| t.annual_cents);

    let tiers: Vec<serde_json::Value> = tier_entries.iter().map(|(id, t)| {
        serde_json::json!({
            "id": id,
            "name": tier_display_name(id),
            "annual_cents": t.annual_cents,
            "enclaves": t.enclaves,
            "vcpu": t.vcpu,
            "ram_gb": t.ram_gb,
            "prices": {
                "monthly": t.cycle_price("monthly", discounts),
                "yearly": t.cycle_price("yearly", discounts),
                "2year": t.cycle_price("2year", discounts),
            },
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "tiers": tiers,
        "extra_block": {
            "annual_cents": extra_block.annual_cents,
            "enclaves": extra_block.enclaves,
            "vcpu": extra_block.vcpu,
            "ram_gb": extra_block.ram_gb,
            "prices": {
                "monthly": calculate_cycle_price(extra_block.annual_cents, "monthly", discounts),
                "yearly": calculate_cycle_price(extra_block.annual_cents, "yearly", discounts),
                "2year": calculate_cycle_price(extra_block.annual_cents, "2year", discounts),
            },
        },
    })))
}

pub async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let row = sqlx::query(
        "SELECT id, user_id, organization_id, tier, billing_period, max_vcpus, max_apps, price_cents_per_cycle,
                extra_vcpu_blocks, extra_app_blocks, extra_block_price_cents_per_cycle, status,
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
    let billing_period: String = row.get("billing_period");
    let price_cents_per_cycle: i64 = row.get("price_cents_per_cycle");
    let extra_block_price: i64 = row.get("extra_block_price_cents_per_cycle");
    let tier_name = state.pricing.subscription_tiers.get(&tier)
        .map(|_| tier_display_name(&tier))
        .unwrap_or_else(|| "Unknown".to_string());

    Ok(Json(serde_json::json!({
        "subscription": {
            "id": row.get::<Uuid, _>("id"),
            "user_id": row.get::<Uuid, _>("user_id"),
            "organization_id": row.get::<Uuid, _>("organization_id"),
            "tier": tier,
            "tier_name": tier_name,
            "billing_period": billing_period,
            "max_vcpus": row.get::<i32, _>("max_vcpus"),
            "max_apps": row.get::<i32, _>("max_apps"),
            "price_cents_per_cycle": price_cents_per_cycle,
            "extra_vcpu_blocks": row.get::<i32, _>("extra_vcpu_blocks"),
            "extra_app_blocks": row.get::<i32, _>("extra_app_blocks"),
            "extra_block_price_cents_per_cycle": extra_block_price,
            "total_price_cents_per_cycle": price_cents_per_cycle + extra_block_price,
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
    #[serde(default = "default_billing_period")]
    billing_period: String,
}

fn default_billing_period() -> String { "monthly".to_string() }

pub async fn subscribe(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tier = state.pricing.subscription_tiers.get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;
    let tier_name = tier_display_name(&req.tier_id);

    if !["monthly", "yearly", "2year"].contains(&req.billing_period.as_str()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid billing_period. Use monthly, yearly, or 2year".to_string()));
    }

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
        return Err((StatusCode::CONFLICT, "Organization already has an active subscription".to_string()));
    }

    let now = Utc::now();
    let price_per_cycle = tier.cycle_price(&req.billing_period, &state.pricing.billing_discounts);
    let period_end = calculate_period_end(now, &req.billing_period);

    // Charge first period: credits first, then Paddle for remainder
    let total_charge = price_per_cycle;

    // Read credit balance (non-binding — final deduction is atomic inside the transaction below)
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .unwrap_or(0);

    let estimated_credits = balance_cents.min(total_charge).max(0);
    let estimated_remainder = total_charge - estimated_credits;

    // If Paddle charge is needed, do it BEFORE creating the subscription
    let mut paddle_txn_id: Option<String> = None;
    let event_status;

    if estimated_remainder > 0 {
        let paddle_customer_id: Option<String> = sqlx::query_scalar(
            "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .flatten();

        if let Some(customer_id) = paddle_customer_id {
            if let Some(ref api_key) = state.paddle_api_key {
                let client = reqwest::Client::new();
                let amount_str = estimated_remainder.to_string();
                let body = serde_json::json!({
                    "customer_id": customer_id,
                    "items": [{
                        "quantity": 1,
                        "price": {
                            "description": format!("{} subscription ({})", tier_name, req.billing_period),
                            "unit_price": {
                                "amount": amount_str,
                                "currency_code": "USD",
                            },
                            "product": {
                                "name": format!("{} Subscription", tier_name),
                                "tax_category": "standard",
                            }
                        }
                    }],
                    "collection_mode": "automatic",
                });

                let response = client
                    .post(format!("{}/transactions", state.paddle_api_url))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle API error: {}", e)))?;

                if response.status().is_success() {
                    let resp: serde_json::Value = response.json().await
                        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {}", e)))?;
                    paddle_txn_id = resp["data"]["id"].as_str().map(|s| s.to_string());
                    event_status = "paid";
                } else {
                    let status = response.status();
                    let err_body = response.text().await.unwrap_or_default();
                    tracing::error!("Paddle subscription charge failed: {} - {}", status, err_body);
                    return Err((StatusCode::PAYMENT_REQUIRED, format!("Payment failed: {}", status)));
                }
            } else {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured".to_string()));
            }
        } else {
            return Err((StatusCode::PAYMENT_REQUIRED, "no_payment_method".to_string()));
        }
    } else {
        event_status = "credits_covered";
    }

    // Payment succeeded (or fully covered by credits) — now create subscription in a transaction
    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let sub_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO subscriptions (user_id, organization_id, tier, billing_period, max_vcpus, max_apps,
         price_cents_per_cycle, current_period_end, next_billing_at, last_billed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, NOW())
         RETURNING id"
    )
    .bind(auth.user_id)
    .bind(org_id)
    .bind(&req.tier_id)
    .bind(&req.billing_period)
    .bind(tier.vcpu)
    .bind(tier.enclaves)
    .bind(price_per_cycle)
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create subscription: {}", e)))?;

    // Atomically lock and deduct credits within the transaction
    // Re-read balance with FOR UPDATE to prevent TOCTOU race
    let locked_balance: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .unwrap_or(0);

    let credits_to_apply = locked_balance.min(total_charge).max(0);
    let remainder_cents = total_charge - credits_to_apply;

    // If we estimated credits would cover more than they actually do, and we didn't charge
    // Paddle enough, we need to fail. This can happen if balance changed between estimate and lock.
    if remainder_cents > 0 && paddle_txn_id.is_none() {
        return Err((StatusCode::PAYMENT_REQUIRED, "Insufficient credits and no payment charged".to_string()));
    }

    if credits_to_apply > 0 {
        sqlx::query(
            "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE organization_id = $2 AND balance_cents >= $1"
        )
        .bind(credits_to_apply)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deduct credits: {}", e)))?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT balance_cents FROM wallet_balance WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        sqlx::query(
            "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'billing_deduction', $4)"
        )
        .bind(org_id)
        .bind(-credits_to_apply)
        .bind(new_balance)
        .bind(format!("Subscription: {} {}", tier_name, req.billing_period))
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record ledger: {}", e)))?;
    }

    // Record billing event
    sqlx::query(
        "INSERT INTO subscription_billing_events
         (subscription_id, user_id, billing_period_start, billing_period_end, tier,
          base_amount_cents, total_amount_cents, credits_applied_cents, charged_amount_cents,
          paddle_transaction_id, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
    )
    .bind(sub_id.0)
    .bind(auth.user_id)
    .bind(now)
    .bind(period_end)
    .bind(&req.tier_id)
    .bind(price_per_cycle)
    .bind(total_charge)
    .bind(credits_to_apply)
    .bind(remainder_cents)
    .bind(&paddle_txn_id)
    .bind(event_status)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record billing event: {}", e)))?;

    // Record invoice
    let invoice_number = format!("INV-SUB-{}", &sub_id.0.to_string()[..8]);
    sqlx::query(
        "INSERT INTO invoices (paddle_transaction_id, user_id, organization_id, invoice_number, amount_cents, currency, status, payment_status, billing_provider, created_at)
         VALUES ($1, $2, $3, $4, $5, 'USD', 'finalized', $6, $7, NOW())"
    )
    .bind(&paddle_txn_id)
    .bind(auth.user_id)
    .bind(org_id)
    .bind(&invoice_number)
    .bind(if remainder_cents == 0 {
        total_charge
    } else {
        remainder_cents
    })
    .bind(if remainder_cents == 0 {
        "credits_applied"
    } else {
        "pending"
    })
    .bind(if remainder_cents == 0 { "credits" } else { "paddle" })
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record invoice: {}", e)))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit: {}", e)))?;

    tracing::info!(
        "Subscription created: sub={}, tier={}, org={}, charge={} cents (credits={}, paddle={})",
        sub_id.0, req.tier_id, org_id, total_charge, credits_to_apply, remainder_cents
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "subscription_id": sub_id.0,
        "tier": req.tier_id,
        "billing_period": req.billing_period,
        "price_cents_per_cycle": price_per_cycle,
        "credits_applied": credits_to_apply,
        "charged": remainder_cents,
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
    let new_tier = state.pricing.subscription_tiers.get(&req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let sub: Option<(Uuid, String, String, i64, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, billing_period, tier, price_cents_per_cycle, current_period_start, current_period_end
         FROM subscriptions WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, billing_period, old_tier_id, old_price, period_start, period_end)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    if old_tier_id == req.tier_id {
        return Err((StatusCode::BAD_REQUEST, "Already on this tier".to_string()));
    }

    let new_price = new_tier.cycle_price(&billing_period, &state.pricing.billing_discounts);

    // Prorate: credit remaining old tier, charge remaining new tier
    let now = Utc::now();
    let total_period_secs = (period_end - period_start).num_seconds().max(1);
    let remaining_secs = (period_end - now).num_seconds().max(0);
    let prorate_fraction = remaining_secs as f64 / total_period_secs as f64;

    let old_credit = (old_price as f64 * prorate_fraction).round() as i64;
    let new_charge = (new_price as f64 * prorate_fraction).round() as i64;
    let net_charge = new_charge - old_credit; // positive = upgrade, negative = downgrade refund

    // If upgrade (net_charge > 0), collect payment
    let mut paddle_charged = false;
    if net_charge > 0 {
        // Check credit balance for estimated coverage
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        let estimated_credits = balance.min(net_charge).max(0);
        let remainder = net_charge - estimated_credits;

        if remainder > 0 {
            let paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1"
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
            .flatten();

            let customer_id = paddle_customer_id
                .ok_or_else(|| (StatusCode::PAYMENT_REQUIRED, "no_payment_method".to_string()))?;
            let api_key = state.paddle_api_key.as_ref()
                .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured".to_string()))?;

            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "customer_id": customer_id,
                "items": [{
                    "quantity": 1,
                    "price": {
                        "description": format!("Tier upgrade proration: {} → {}", old_tier_id, req.tier_id),
                        "unit_price": { "amount": remainder.to_string(), "currency_code": "USD" },
                        "product": { "name": "Subscription Tier Upgrade", "tax_category": "standard" }
                    }
                }],
                "collection_mode": "automatic",
            });

            let response = client
                .post(format!("{}/transactions", state.paddle_api_url))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle API error: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let err_body = response.text().await.unwrap_or_default();
                tracing::error!("Paddle tier change charge failed: {} - {}", status, err_body);
                return Err((StatusCode::PAYMENT_REQUIRED, format!("Payment failed: {}", status)));
            }
            paddle_charged = true;
        }
    }

    // Payment succeeded (or downgrade/credit-covered) — apply changes atomically
    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    sqlx::query(
        "UPDATE subscriptions SET tier = $1, max_vcpus = $2, max_apps = $3, price_cents_per_cycle = $4, updated_at = NOW()
         WHERE id = $5"
    )
    .bind(&req.tier_id)
    .bind(new_tier.vcpu)
    .bind(new_tier.enclaves)
    .bind(new_price)
    .bind(sub_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Apply credit adjustments atomically
    if net_charge > 0 {
        // Upgrade: deduct credits
        let locked_balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        let credits_to_apply = locked_balance.min(net_charge).max(0);
        let remainder_after_lock = net_charge - credits_to_apply;

        if remainder_after_lock > 0 && !paddle_charged {
            return Err((StatusCode::PAYMENT_REQUIRED, "Insufficient credits and no payment charged".to_string()));
        }

        if credits_to_apply > 0 {
            sqlx::query(
                "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE organization_id = $2 AND balance_cents >= $1"
            )
            .bind(credits_to_apply)
            .bind(org_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deduct credits: {}", e)))?;

            let new_balance: i64 = sqlx::query_scalar(
                "SELECT balance_cents FROM wallet_balance WHERE organization_id = $1"
            )
            .bind(org_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

            sqlx::query(
                "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description)
                 Values ($1, $2, $3, 'billing_deduction', $4)"
            )
            .bind(org_id)
            .bind(-credits_to_apply)
            .bind(new_balance)
            .bind(format!("Tier upgrade proration: {} → {}", old_tier_id, req.tier_id))
            .execute(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record ledger: {}", e)))?;
        }
    } else if net_charge < 0 {
        // Downgrade: refund the difference as credits
        let refund_cents = -net_charge;
        sqlx::query(
            "INSERT INTO wallet_balance (organization_id, balance_cents)
             VALUES ($1, $2)
             ON CONFLICT (organization_id) DO UPDATE SET balance_cents = wallet_balance.balance_cents + $2"
        )
        .bind(org_id)
        .bind(refund_cents)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to refund credits: {}", e)))?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT balance_cents FROM wallet_balance WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        sqlx::query(
            "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'proration_refund', $4)"
        )
        .bind(org_id)
        .bind(refund_cents)
        .bind(new_balance)
        .bind(format!("Tier downgrade proration: {} → {}", old_tier_id, req.tier_id))
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record ledger: {}", e)))?;
    }

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit: {}", e)))?;

    tracing::info!(
        "Subscription {} tier changed {} → {} (prorated: old_credit={}c, new_charge={}c, net={}c)",
        sub_id, old_tier_id, req.tier_id, old_credit, new_charge, net_charge
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "new_tier": req.tier_id,
        "new_price_cents_per_cycle": new_price,
        "prorated_credit_cents": old_credit,
        "prorated_charge_cents": new_charge,
        "net_charge_cents": net_charge,
        "effective": "immediate",
    })))
}

#[derive(Deserialize)]
pub struct AddCapacityRequest {
    vcpu_blocks: Option<i32>,
    app_blocks: Option<i32>,
}

pub async fn add_subscription_capacity(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<AddCapacityRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let sub: Option<(Uuid, String, i32, i32, i64, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, billing_period, extra_vcpu_blocks, extra_app_blocks, extra_block_price_cents_per_cycle,
                current_period_start, current_period_end
         FROM subscriptions WHERE organization_id = $1 AND status = 'active' LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, billing_period, cur_vcpu_blocks, cur_app_blocks, cur_extra_price, period_start, period_end)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    let add_vcpu = req.vcpu_blocks.unwrap_or(0).max(0);
    let add_app = req.app_blocks.unwrap_or(0).max(0);
    let total_new_blocks = add_vcpu + add_app;

    if total_new_blocks == 0 {
        return Err((StatusCode::BAD_REQUEST, "Must add at least one block".to_string()));
    }

    let block_price_per_cycle = calculate_cycle_price(state.pricing.extra_block.annual_cents, &billing_period, &state.pricing.billing_discounts);
    let additional_price = block_price_per_cycle * total_new_blocks as i64;

    // Prorate: charge only for remaining portion of current period
    let now = Utc::now();
    let total_period_secs = (period_end - period_start).num_seconds().max(1);
    let remaining_secs = (period_end - now).num_seconds().max(0);
    let prorate_fraction = remaining_secs as f64 / total_period_secs as f64;
    let prorated_charge = (additional_price as f64 * prorate_fraction).round() as i64;

    let new_vcpu_blocks = cur_vcpu_blocks + add_vcpu;
    let new_app_blocks = cur_app_blocks + add_app;
    let new_extra_price = cur_extra_price + additional_price;

    // Collect payment BEFORE updating capacity
    // Read balance as estimate for Paddle charge calculation; final deduction is atomic in the tx
    let mut paddle_charged = false;
    if prorated_charge > 0 {
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        let estimated_credits = balance.min(prorated_charge).max(0);
        let remainder = prorated_charge - estimated_credits;

        if remainder > 0 {
            // Charge via Paddle — must succeed before we update capacity
            let paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1"
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
            .flatten();

            let customer_id = paddle_customer_id
                .ok_or_else(|| (StatusCode::PAYMENT_REQUIRED, "no_payment_method".to_string()))?;
            let api_key = state.paddle_api_key.as_ref()
                .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured".to_string()))?;

            let client = reqwest::Client::new();
            let amount_str = remainder.to_string();
            let body = serde_json::json!({
                "customer_id": customer_id,
                "items": [{
                    "quantity": 1,
                    "price": {
                        "description": format!("Extra capacity blocks (prorated)"),
                        "unit_price": { "amount": amount_str, "currency_code": "USD" },
                        "product": { "name": "Extra Capacity Block", "tax_category": "standard" }
                    }
                }],
                "collection_mode": "automatic",
            });

            let response = client
                .post(format!("{}/transactions", state.paddle_api_url))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle API error: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let err_body = response.text().await.unwrap_or_default();
                tracing::error!("Paddle capacity charge failed: {} - {}", status, err_body);
                return Err((StatusCode::PAYMENT_REQUIRED, format!("Payment failed: {}", status)));
            }
            paddle_charged = true;
        }
    }

    // Payment succeeded — now update capacity and apply credits atomically
    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    sqlx::query(
        "UPDATE subscriptions SET
         extra_vcpu_blocks = $1, extra_app_blocks = $2,
         extra_block_price_cents_per_cycle = $3,
         max_vcpus = max_vcpus + $4, max_apps = CASE WHEN max_apps = -1 THEN -1 ELSE max_apps + $5 END,
         updated_at = NOW()
         WHERE id = $6"
    )
    .bind(new_vcpu_blocks)
    .bind(new_app_blocks)
    .bind(new_extra_price)
    .bind(add_vcpu * state.pricing.extra_block.vcpu)
    .bind(add_app * state.pricing.extra_block.enclaves)
    .bind(sub_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Atomically lock and deduct credits within the transaction
    let locked_balance: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE organization_id = $1 FOR UPDATE"
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .unwrap_or(0);

    let credits_applied = locked_balance.min(prorated_charge).max(0);
    let remainder_after_lock = prorated_charge - credits_applied;

    if remainder_after_lock > 0 && !paddle_charged {
        return Err((StatusCode::PAYMENT_REQUIRED, "Insufficient credits and no payment charged".to_string()));
    }

    if credits_applied > 0 {
        sqlx::query(
            "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE organization_id = $2 AND balance_cents >= $1"
        )
        .bind(credits_applied)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deduct credits: {}", e)))?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT balance_cents FROM wallet_balance WHERE organization_id = $1"
        )
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        sqlx::query(
            "INSERT INTO credit_ledger (organization_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'billing_deduction', 'Subscription capacity addon (prorated)')"
        )
        .bind(org_id)
        .bind(-credits_applied)
        .bind(new_balance)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record ledger: {}", e)))?;
    }

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit: {}", e)))?;

    tracing::info!("Added {} vCPU blocks + {} app blocks to sub {}, prorated charge: {} cents",
        add_vcpu, add_app, sub_id, prorated_charge);

    Ok(Json(serde_json::json!({
        "success": true,
        "extra_vcpu_blocks": new_vcpu_blocks,
        "extra_app_blocks": new_app_blocks,
        "prorated_charge_cents": prorated_charge,
    })))
}

pub async fn cancel_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let sub: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, current_period_end FROM subscriptions WHERE organization_id = $1 AND status = 'active' LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, period_end)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    sqlx::query(
        "UPDATE subscriptions SET cancel_at_period_end = true, canceled_at = NOW(), updated_at = NOW() WHERE id = $1"
    )
    .bind(sub_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    tracing::info!("Subscription {} set to cancel at period end ({})", sub_id, period_end);

    Ok(Json(serde_json::json!({
        "success": true,
        "cancel_at_period_end": true,
        "active_until": period_end,
    })))
}

pub async fn reactivate_subscription(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let sub: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, cancel_at_period_end FROM subscriptions WHERE organization_id = $1 AND status = 'active' LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, cancel_pending)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    if !cancel_pending {
        return Err((StatusCode::BAD_REQUEST, "Subscription is not pending cancellation".to_string()));
    }

    sqlx::query(
        "UPDATE subscriptions SET cancel_at_period_end = false, canceled_at = NULL, updated_at = NOW() WHERE id = $1"
    )
    .bind(sub_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    tracing::info!("Subscription {} reactivated", sub_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "cancel_at_period_end": false,
    })))
}

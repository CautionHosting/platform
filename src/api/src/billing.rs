use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Datelike, Utc};
use serde::Deserialize;
use sqlx::{Executor, PgPool, Postgres, Row};
use std::sync::Arc;
use uuid::Uuid;

use crate::{get_user_primary_org, AppState, AuthContext, PricingConfig};

/// Base AWS on-demand rates by instance type (USD/hr, us-west-2).
/// Used by both compute metering and builder billing.
pub(crate) fn base_instance_rate(instance_type: &str) -> Option<f64> {
    Some(match instance_type {
        "m5.xlarge" => 0.192,
        "m5.2xlarge" => 0.384,
        "m5.4xlarge" => 0.768,
        "m5.8xlarge" => 1.536,
        "m5.12xlarge" => 2.304,
        "m5.16xlarge" => 3.072,
        "m5.24xlarge" => 4.608,
        "c5.xlarge" => 0.17,
        "c5.2xlarge" => 0.34,
        "c5.4xlarge" => 0.68,
        "c6i.xlarge" => 0.17,
        "c6i.2xlarge" => 0.34,
        "c6a.xlarge" => 0.153,
        "c6a.2xlarge" => 0.306,
        _ => return None,
    })
}
use crate::suspension::call_internal_unsuspend;
use serde::Serialize;

#[derive(Debug, sqlx::FromRow)]
struct BillingUsageRow {
    id: Option<Uuid>,
    resource_id: String,
    resource_name: String,
    resource_type: String,
    quantity: f64,
    unit: String,
    rate: f64,
    cost: f64,
}

#[derive(Debug, sqlx::FromRow)]
struct SubscriptionSpendRow {
    subscription_id: Uuid,
    tier: String,
    quantity: f64,
    rate: f64,
    cost: f64,
    projected_cost: f64,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct CreditPackage {
    pub(crate) purchase_cents: i64,
    pub(crate) credit_cents: i64,
    pub(crate) bonus_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) paddle_price_id: Option<String>,
}

// Credit package base amounts (purchase_cents). Bonus percentages come from prices.json.
const CREDIT_PACKAGE_BASES: &[(i64, &str)] =
    &[(100_000, "1000"), (500_000, "5000"), (2_500_000, "25000")];

pub(crate) fn build_credit_packages(
    pricing: &PricingConfig,
    paddle_ids: &[Option<String>; 3],
) -> Vec<CreditPackage> {
    CREDIT_PACKAGE_BASES
        .iter()
        .enumerate()
        .map(|(i, &(purchase_cents, key))| {
            let bonus_percent = pricing.credit_bonus_percent(key);
            let credit_cents =
                purchase_cents + (purchase_cents as f64 * bonus_percent / 100.0) as i64;
            CreditPackage {
                purchase_cents,
                credit_cents,
                bonus_percent,
                paddle_price_id: paddle_ids[i].clone(),
            }
        })
        .collect()
}

pub async fn get_ledger_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> Result<i64, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        r#"
        SELECT COALESCE(clb.credit_cents, 0) - COALESCE(dlb.debit_cents, 0)
        FROM (SELECT $1::uuid AS organization_id) org
        LEFT JOIN credit_ledger_balances clb USING (organization_id)
        LEFT JOIN debit_ledger_balances dlb USING (organization_id)
        "#,
    )
    .bind(organization_id)
    .fetch_one(executor)
    .await
}

pub async fn get_debit_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> Result<i64, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        r#"
        SELECT COALESCE(dlb.debit_cents, 0)
        FROM (SELECT $1::uuid AS organization_id) org
        LEFT JOIN debit_ledger_balances dlb USING (organization_id)
        "#,
    )
    .bind(organization_id)
    .fetch_one(executor)
    .await
}

pub async fn get_billing_usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let now = chrono::Utc::now();

    // Calculate billing period (first of current month to end of month)
    let first_of_month_naive = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap();
    let first_of_month_dt = first_of_month_naive.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let next_month_naive = if now.month() == 12 {
        chrono::NaiveDate::from_ymd_opt(now.year() + 1, 1, 1).unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(now.year(), now.month() + 1, 1).unwrap()
    };
    let days_in_month = next_month_naive
        .signed_duration_since(first_of_month_naive)
        .num_days() as f64;
    let next_month_dt = next_month_naive.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let billing_period_seconds = next_month_dt
        .signed_duration_since(first_of_month_dt)
        .num_seconds();
    let elapsed_seconds = now.signed_duration_since(first_of_month_dt).num_seconds();
    let projection_multiplier = if elapsed_seconds > 0 {
        billing_period_seconds as f64 / elapsed_seconds as f64
    } else {
        days_in_month * 24.0
    };

    let total_debits_cents = get_debit_balance_cents(&state.db, org_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    let usage_rows: Vec<BillingUsageRow> = sqlx::query_as(
        r#"
        WITH monthly_usage AS (
            SELECT
                ul.application_id AS id,
                ul.resource_id,
                COALESCE(
                    NULLIF(cr.resource_name, ''),
                    NULLIF(ul.metadata->>'resource_name', ''),
                    ul.resource_id
                ) AS resource_name,
                ul.resource_type,
                ul.unit,
                (
                    COALESCE(ul.base_unit_cost_usd, 0)
                    * (1 + COALESCE(ul.margin_percent, 0) / 100.0)
                )::double precision AS rate,
                ul.quantity::double precision AS quantity,
                (
                    ul.quantity
                    * COALESCE(ul.base_unit_cost_usd, 0)
                    * (1 + COALESCE(ul.margin_percent, 0) / 100.0)
                )::double precision AS cost
            FROM usage_ledger ul
            LEFT JOIN compute_resources cr
                ON cr.id = ul.application_id
               AND cr.organization_id = ul.organization_id
            WHERE ul.organization_id = $1
              AND ul.recorded_at >= $2
              AND ul.recorded_at < $3
        )
        SELECT
            id,
            MIN(resource_id) AS resource_id,
            resource_name,
            resource_type,
            SUM(quantity)::double precision AS quantity,
            unit,
            rate,
            SUM(cost)::double precision AS cost
        FROM monthly_usage
        GROUP BY id, resource_name, resource_type, unit, rate
        ORDER BY cost DESC, resource_name ASC, resource_type ASC
        "#,
    )
    .bind(org_id)
    .bind(first_of_month_dt)
    .bind(next_month_dt)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let subscription_rows: Vec<SubscriptionSpendRow> = sqlx::query_as(
        r#"
        WITH monthly_subscription_spend AS (
            SELECT
                sl.subscription_id,
                sl.tier,
                GREATEST(
                    EXTRACT(
                        EPOCH FROM
                            LEAST(COALESCE(sl.billing_period_end, $3), $3)
                            - GREATEST(sl.billing_period_start, $2)
                    ) / 3600.0,
                    0
                )::double precision AS quantity,
                sl.cost_hourly::double precision AS rate,
                GREATEST(
                    EXTRACT(
                        EPOCH FROM
                            LEAST(COALESCE(sl.billing_period_end, $3), $3)
                            - GREATEST(sl.billing_period_start, $2)
                    ) / 3600.0
                    * sl.cost_hourly,
                    0
                )::double precision AS cost,
                GREATEST(
                    EXTRACT(
                        EPOCH FROM
                            LEAST(COALESCE(sl.billing_period_end, $4), $4)
                            - GREATEST(sl.billing_period_start, $2)
                    ) / 3600.0
                    * sl.cost_hourly,
                    0
                )::double precision AS projected_cost
            FROM subscription_ledger sl
            WHERE sl.organization_id = $1
              AND sl.billing_period_start < $4
              AND COALESCE(sl.billing_period_end, $4) > $2
        )
        SELECT
            subscription_id,
            tier,
            SUM(quantity)::double precision AS quantity,
            rate,
            SUM(cost)::double precision AS cost,
            SUM(projected_cost)::double precision AS projected_cost
        FROM monthly_subscription_spend
        GROUP BY subscription_id, tier, rate
        HAVING SUM(cost) > 0 OR SUM(projected_cost) > 0
        ORDER BY cost DESC, tier ASC
        "#,
    )
    .bind(org_id)
    .bind(first_of_month_dt)
    .bind(now)
    .bind(next_month_dt)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let total_cost = total_debits_cents as f64 / 100.0;
    let mut total_projected = total_cost;
    let mut items = Vec::new();
    let mut subscription_items = Vec::new();

    for row in usage_rows {
        let projected_cost = row.cost * projection_multiplier.max(1.0);

        total_projected += (projected_cost - row.cost).max(0.0);

        items.push(serde_json::json!({
            "id": row.id,
            "resource_id": row.resource_id,
            "resource_name": row.resource_name,
            "resource_type": row.resource_type,
            "quantity": row.quantity,
            "unit": row.unit,
            "rate": format!("{:.2}", row.rate),
            "cost": row.cost,
            "projected_cost": projected_cost,
        }));
    }

    for row in subscription_rows {
        total_projected += (row.projected_cost - row.cost).max(0.0);

        subscription_items.push(serde_json::json!({
            "id": format!("{}:{}:{:.6}", row.subscription_id, row.tier, row.rate),
            "subscription_id": row.subscription_id,
            "tier": row.tier,
            "resource_name": crate::subscriptions::tier_display_name(&row.tier),
            "resource_type": "subscription",
            "quantity": row.quantity,
            "unit": "hours",
            "rate": format!("{:.2}", row.rate),
            "cost": row.cost,
            "projected_cost": row.projected_cost,
        }));
    }

    Ok(Json(serde_json::json!({
        "total_cost": total_cost,
        "projected_cost": total_projected,
        "currency": "USD",
        "billing_period_start": first_of_month_naive.to_string(),
        "billing_period_end": next_month_naive.to_string(),
        "items": items,
        "subscription_items": subscription_items,
    })))
}

/// Get billing invoices
pub async fn get_billing_invoices(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Query invoices from database
    let invoices: Vec<(
        Uuid,
        String,
        i64,
        String,
        Option<String>,
        chrono::NaiveDateTime,
    )> = sqlx::query_as(
        "SELECT id, invoice_number, amount_cents, status, pdf_url, created_at
         FROM invoices
         WHERE organization_id = $1
         ORDER BY created_at DESC
         LIMIT 50",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let invoice_list: Vec<serde_json::Value> = invoices
        .iter()
        .map(|(id, number, amount, status, pdf_url, date)| {
            serde_json::json!({
                "id": id,
                "number": number,
                "amount_cents": amount,
                "status": status,
                "pdf_url": pdf_url,
                "date": date.to_string(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "invoices": invoice_list,
    })))
}

/// Get all active payment methods
pub async fn get_payment_methods(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let rows: Vec<(
        Uuid,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    )> = sqlx::query_as(
        "SELECT id, payment_type, last4, card_brand, email, is_primary
         FROM payment_methods
         WHERE organization_id = $1 AND is_active = true
         ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let methods: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, payment_type, last4, card_brand, email, is_primary)| {
            serde_json::json!({
                "id": id,
                "type": payment_type,
                "last4": last4,
                "card_brand": card_brand,
                "email": email,
                "is_primary": is_primary,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "payment_methods": methods
    })))
}

/// Delete a specific payment method by ID
pub async fn delete_payment_method(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(method_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Verify the method belongs to this org and get its primary status
    let method: Option<(bool,)> = sqlx::query_as(
        "SELECT is_primary FROM payment_methods WHERE id = $1 AND organization_id = $2 AND is_active = true"
    )
    .bind(method_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((was_primary,)) = method else {
        return Err((
            StatusCode::NOT_FOUND,
            "Payment method not found".to_string(),
        ));
    };

    // Block deletion if this is the last active payment method and org has running resources
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true",
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    if active_count <= 1 {
        return Err((StatusCode::CONFLICT,
            "You must have at least one payment method on file. Add another payment method before removing this one.".to_string()));
    }

    // Soft-delete
    sqlx::query("UPDATE payment_methods SET is_active = false, is_primary = false WHERE id = $1")
        .bind(method_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    // If deleted method was primary, promote the most recent remaining card
    if was_primary {
        sqlx::query(
            "UPDATE payment_methods SET is_primary = true
             WHERE id = (
                SELECT id FROM payment_methods
                WHERE organization_id = $1 AND is_active = true
                ORDER BY created_at DESC LIMIT 1
             )",
        )
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Set a payment method as primary
pub async fn set_primary_payment_method(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(method_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Verify the method belongs to this org
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM payment_methods WHERE id = $1 AND organization_id = $2 AND is_active = true"
    )
    .bind(method_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Payment method not found".to_string(),
        ));
    }

    // Atomically swap primary in a transaction
    let mut tx = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    sqlx::query(
        "UPDATE payment_methods SET is_primary = false WHERE organization_id = $1 AND is_active = true"
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    sqlx::query("UPDATE payment_methods SET is_primary = true WHERE id = $1")
        .bind(method_id)
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
            format!("Database error: {}", e),
        )
    })?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Get Paddle client token and customer ID for frontend Paddle.js initialization
pub async fn get_paddle_client_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let client_token = state.paddle_client_token.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle is not configured".to_string(),
        )
    })?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Get the org's Paddle customer ID if one exists
    let paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?
    .flatten();

    Ok(Json(serde_json::json!({
        "client_token": client_token,
        "paddle_customer_id": paddle_customer_id,
        "setup_price_id": state.paddle_setup_price_id,
    })))
}

#[derive(Deserialize)]
pub struct PaddleTransactionCompletedRequest {
    transaction_id: String,
    #[serde(default)]
    card_last4: Option<String>,
    #[serde(default)]
    card_brand: Option<String>,
}

fn is_completed_paddle_transaction_status(status: &str) -> bool {
    matches!(status, "completed" | "paid" | "billed")
}

fn extract_paddle_payment_method_id(txn: &serde_json::Value) -> Option<String> {
    txn["data"]["payments"].as_array().and_then(|payments| {
        payments.iter().find_map(|payment| {
            payment["payment_method_id"]
                .as_str()
                .or_else(|| payment["stored_payment_method_id"].as_str())
                .map(|id| id.to_string())
        })
    })
}

fn transaction_contains_price_id(txn: &serde_json::Value, expected_price_id: &str) -> bool {
    let matches_price = |item: &serde_json::Value| {
        item["price_id"].as_str() == Some(expected_price_id)
            || item["price"]["id"].as_str() == Some(expected_price_id)
    };

    txn["data"]["items"]
        .as_array()
        .map(|items| items.iter().any(matches_price))
        .unwrap_or(false)
        || txn["data"]["details"]["line_items"]
            .as_array()
            .map(|items| items.iter().any(matches_price))
            .unwrap_or(false)
}

fn validate_paddle_setup_transaction(
    txn: &serde_json::Value,
    expected_setup_price_id: &str,
    expected_customer_id: Option<&str>,
    expected_customer_email: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let status = txn["data"]["status"].as_str().unwrap_or("");
    if !is_completed_paddle_transaction_status(status) {
        return Err(format!("Transaction not completed (status: {})", status));
    }

    if txn["data"]["collection_mode"].as_str().unwrap_or("") != "automatic" {
        return Err("Transaction is not an automatic checkout".to_string());
    }

    if !transaction_contains_price_id(txn, expected_setup_price_id) {
        return Err("Transaction does not match the configured setup price".to_string());
    }

    let customer_id = txn["data"]["customer_id"]
        .as_str()
        .ok_or_else(|| "Transaction has no customer_id".to_string())?;

    if let Some(expected_customer_id) = expected_customer_id {
        if customer_id != expected_customer_id {
            return Err("Transaction does not belong to this account".to_string());
        }
    } else {
        let expected_customer_email = expected_customer_email
            .ok_or_else(|| "No billing customer or verified email on file".to_string())?;
        let txn_customer_email = txn["data"]["customer"]["email"]
            .as_str()
            .ok_or_else(|| "Transaction customer email is unavailable".to_string())?;
        if !txn_customer_email.eq_ignore_ascii_case(expected_customer_email) {
            return Err("Transaction does not belong to this account".to_string());
        }
    }

    Ok((
        customer_id.to_string(),
        extract_paddle_payment_method_id(txn),
    ))
}

/// Frontend callback after Paddle checkout completion — records payment method reference locally
pub async fn paddle_transaction_completed(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PaddleTransactionCompletedRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle API not configured".to_string(),
        )
    })?;
    let setup_price_id = state.paddle_setup_price_id.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Paddle setup price not configured".to_string(),
        )
    })?;

    let existing_paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?
    .flatten();

    let user_email: Option<String> = if existing_paddle_customer_id.is_none() {
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?
            .flatten()
    } else {
        None
    };

    let txn = fetch_paddle_transaction(&state.paddle_api_url, paddle_api_key, &req.transaction_id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to verify transaction: {}", e),
            )
        })?;

    let (customer_id, paddle_payment_method_id) = validate_paddle_setup_transaction(
        &txn,
        setup_price_id,
        existing_paddle_customer_id.as_deref(),
        user_email.as_deref(),
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Check if the org already has any active payment methods
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true",
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let is_primary = existing_count == 0;

    // Save the new payment method reference (keep existing methods active)
    sqlx::query(
        "INSERT INTO payment_methods (id, organization_id, payment_type, provider_token, paddle_payment_method_id, last4, card_brand, is_active, is_primary, created_at)
         VALUES ($1, $2, 'card', $3, $4, $5, $6, true, $7, NOW())"
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&req.transaction_id)
    .bind(&paddle_payment_method_id)
    .bind(&req.card_last4)
    .bind(&req.card_brand)
    .bind(is_primary)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if let Err(e) = sqlx::query(
        "INSERT INTO billing_config (organization_id, paddle_customer_id)
         VALUES ($1, $2)
         ON CONFLICT (organization_id) DO UPDATE SET paddle_customer_id = $2",
    )
    .bind(org_id)
    .bind(&customer_id)
    .execute(&state.db)
    .await
    {
        tracing::error!(
            "Failed to store paddle_customer_id for org {}: {}",
            org_id,
            e
        );
    } else {
        tracing::info!(
            "Stored paddle_customer_id {} for org {}",
            customer_id,
            org_id
        );
    }

    tracing::info!(
        "Paddle transaction {} completed for org {}",
        req.transaction_id,
        org_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "transaction_id": req.transaction_id,
    })))
}

async fn fetch_paddle_transaction(
    api_url: &str,
    api_key: &str,
    transaction_id: &str,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/transactions/{}", api_url, transaction_id))
        .query(&[("include", "customer")])
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("Paddle API error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Paddle API returned {}", resp.status()));
    }

    resp.json().await.map_err(|e| format!("Parse error: {}", e))
}

/// Fetch the customer_id from a Paddle transaction
pub async fn fetch_paddle_customer_id_from_txn(
    api_url: &str,
    api_key: &str,
    transaction_id: &str,
) -> Result<String, String> {
    let body = fetch_paddle_transaction(api_url, api_key, transaction_id).await?;

    body["data"]["customer_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No customer_id in transaction".to_string())
}

pub async fn get_credit_balance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let balance_cents = get_ledger_balance_cents(&state.db, org_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    Ok(Json(serde_json::json!({
        "balance_cents": balance_cents,
        "balance_display": format!("${:.2}", balance_cents as f64 / 100.0),
    })))
}

pub async fn get_credit_packages(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let packages: Vec<serde_json::Value> = credit_packages
        .iter()
        .map(|pkg| {
            serde_json::json!({
                "purchase_cents": pkg.purchase_cents,
                "credit_cents": pkg.credit_cents,
                "bonus_percent": pkg.bonus_percent,
                "purchase_display": format!("${}", pkg.purchase_cents / 100),
                "credit_display": format!("${}", pkg.credit_cents / 100),
                "paddle_price_id": pkg.paddle_price_id,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "packages": packages })))
}

#[derive(Deserialize)]
pub struct PurchaseCreditsRequest {
    /// Set by frontend after inline checkout completes (fallback flow)
    #[serde(default)]
    transaction_id: Option<String>,
    package_index: usize,
}

pub async fn purchase_credits(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PurchaseCreditsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let pkg = credit_packages
        .get(req.package_index)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid package index".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Determine the transaction_id — either provided by frontend (checkout flow)
    // or created server-side using saved payment method
    let transaction_id =
        if let Some(txn_id) = req.transaction_id {
            // Verify the transaction with Paddle before accepting
            let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Paddle API not configured".to_string(),
                )
            })?;

            let client = reqwest::Client::new();
            let verify_resp = client
                .get(format!("{}/transactions/{}", state.paddle_api_url, txn_id))
                .header("Authorization", format!("Bearer {}", paddle_api_key))
                .send()
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to verify transaction: {}", e),
                    )
                })?;

            if !verify_resp.status().is_success() {
                tracing::warn!(
                    "Paddle transaction verification failed for txn_id={}: {}",
                    txn_id,
                    verify_resp.status()
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid transaction ID".to_string(),
                ));
            }

            let verify_data: serde_json::Value = verify_resp.json().await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to parse Paddle response: {}", e),
                )
            })?;

            let txn_status = verify_data["data"]["status"].as_str().unwrap_or("");
            if txn_status != "completed" && txn_status != "paid" && txn_status != "billed" {
                tracing::warn!(
                    "Paddle transaction {} has status '{}', not completed",
                    txn_id,
                    txn_status
                );
                return Err((
                    StatusCode::PAYMENT_REQUIRED,
                    format!("Transaction not completed (status: {})", txn_status),
                ));
            }

            // Verify transaction amount matches the selected package price
            let txn_total = verify_data["data"]["details"]["totals"]["total"]
                .as_str()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            if txn_total != pkg.purchase_cents {
                tracing::warn!(
                    "Paddle transaction {} amount {} does not match package price {}",
                    txn_id,
                    txn_total,
                    pkg.purchase_cents
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Transaction amount does not match package price".to_string(),
                ));
            }

            // Verify transaction belongs to this org's Paddle customer
            let txn_customer_id = verify_data["data"]["customer_id"].as_str().unwrap_or("");
            let org_paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?
            .flatten();

            if let Some(ref expected_cid) = org_paddle_customer_id {
                if txn_customer_id != expected_cid.as_str() {
                    tracing::warn!(
                    "Paddle transaction {} customer_id '{}' does not match user's customer_id '{}'",
                    txn_id, txn_customer_id, expected_cid
                );
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Transaction does not belong to this account".to_string(),
                    ));
                }
            } else {
                tracing::warn!(
                    "Org {} has no paddle_customer_id on file, cannot verify transaction ownership",
                    org_id
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    "No billing account on file".to_string(),
                ));
            }

            txn_id
        } else {
            // Try to charge the card on file via Paddle API
            let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Paddle API not configured".to_string(),
                )
            })?;

            // Try billing_config first, then resolve from an existing payment method transaction
            let mut paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?
            .flatten();

            // If no billing_config row, resolve customer_id from an existing payment method's transaction
            if paddle_customer_id.is_none() {
                let existing_txn: Option<String> = sqlx::query_scalar(
                    "SELECT provider_token FROM payment_methods
                 WHERE organization_id = $1 AND is_active = true AND provider_token IS NOT NULL
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

                if let Some(txn_id) = existing_txn {
                    if let Ok(cid) = fetch_paddle_customer_id_from_txn(
                        &state.paddle_api_url,
                        paddle_api_key,
                        &txn_id,
                    )
                    .await
                    {
                        // Cache it in billing_config for future use
                        if let Err(e) = sqlx::query(
                            "INSERT INTO billing_config (organization_id, paddle_customer_id)
                         VALUES ($1, $2)
                         ON CONFLICT (organization_id) DO UPDATE SET paddle_customer_id = $2",
                        )
                        .bind(org_id)
                        .bind(&cid)
                        .execute(&state.db)
                        .await
                        {
                            tracing::error!(
                                "Failed to cache paddle_customer_id for org {}: {}",
                                org_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "Resolved and cached paddle_customer_id {} for org {}",
                                cid,
                                org_id
                            );
                        }
                        paddle_customer_id = Some(cid);
                    }
                }
            }

            let customer_id = paddle_customer_id.ok_or_else(|| {
                (
                    StatusCode::PAYMENT_REQUIRED,
                    "no_payment_method".to_string(),
                )
            })?;

            // Get price ID for this package
            let price_id = state.paddle_credits_price_ids[req.package_index]
                .as_ref()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "Credit package price not configured".to_string(),
                    )
                })?;

            // Create transaction via Paddle API — automatic collection charges saved payment method
            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "customer_id": customer_id,
                "items": [{
                    "price_id": price_id,
                    "quantity": 1,
                }],
                "collection_mode": "automatic",
            });

            let response = client
                .post(format!("{}/transactions", state.paddle_api_url))
                .header("Authorization", format!("Bearer {}", paddle_api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle API error: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let err_body = response.text().await.unwrap_or_default();
                tracing::error!("Paddle transaction failed: {} - {}", status, err_body);
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("Paddle payment failed: {}", status),
                ));
            }

            let resp: serde_json::Value = response.json().await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Paddle response parse error: {}", e),
                )
            })?;

            let txn_id = resp["data"]["id"]
                .as_str()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_GATEWAY,
                        "Missing transaction ID in Paddle response".to_string(),
                    )
                })?
                .to_string();

            tracing::info!(
                "Created Paddle transaction {} for credit purchase (card on file)",
                txn_id
            );
            txn_id
        };

    // Idempotency: check if this transaction was already processed
    let already_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credit_ledger WHERE paddle_transaction_id = $1)",
    )
    .bind(&transaction_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    if already_exists {
        let balance_cents = get_ledger_balance_cents(&state.db, org_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?;

        return Ok(Json(serde_json::json!({
            "success": true,
            "balance_cents": balance_cents,
            "balance_display": format!("${:.2}", balance_cents as f64 / 100.0),
            "already_processed": true,
        })));
    }

    let description = format!(
        "Credit purchase: ${} → ${} credits ({}% bonus)",
        pkg.purchase_cents / 100,
        pkg.credit_cents / 100,
        pkg.bonus_percent,
    );

    let new_balance = apply_credit(
        &state.db,
        org_id,
        auth.user_id,
        pkg.credit_cents,
        "purchase",
        &description,
        Some(&transaction_id),
        None,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to apply credit: {}", e),
        )
    })?;

    tracing::info!(
        "Credit purchase: org={}, user={}, txn={}, +{} cents, new_balance={}",
        org_id,
        auth.user_id,
        transaction_id,
        pkg.credit_cents,
        new_balance
    );

    // Check if org was credit-suspended and unsuspend if balance is now positive
    if new_balance > 0 {
        if let Ok(org_id) = get_user_primary_org(&state.db, auth.user_id).await {
            let suspended: Option<chrono::DateTime<chrono::Utc>> =
                sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                    .bind(org_id)
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten()
                    .flatten();

            if suspended.is_some() {
                tracing::info!(
                    "Clearing credit suspension for org {} after credit purchase",
                    org_id
                );
                if let Err(e) =
                    sqlx::query("UPDATE organizations SET credit_suspended_at = NULL WHERE id = $1")
                        .bind(org_id)
                        .execute(&state.db)
                        .await
                {
                    tracing::error!(
                        "Failed to clear credit suspension for org {}: {}",
                        org_id,
                        e
                    );
                }

                // Trigger unsuspend via internal endpoint
                let _ = call_internal_unsuspend(&state, org_id).await;
            }
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "balance_cents": new_balance,
        "balance_display": format!("${:.2}", new_balance as f64 / 100.0),
    })))
}

pub async fn get_credit_ledger(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let rows: Vec<(Uuid, i64, i64, String, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, delta_cents,
                (SUM(delta_cents) OVER (PARTITION BY organization_id ORDER BY created_at, id))::bigint AS balance_after,
                entry_type, description, paddle_transaction_id, created_at
         FROM credit_ledger
         WHERE organization_id = $1
         ORDER BY created_at DESC
         LIMIT 50"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(
            |(id, delta, balance_after, entry_type, desc, txn_id, created_at)| {
                serde_json::json!({
                    "id": id,
                    "delta_cents": delta,
                    "balance_after": balance_after,
                    "entry_type": entry_type,
                    "description": desc,
                    "paddle_transaction_id": txn_id,
                    "created_at": created_at,
                })
            },
        )
        .collect();

    Ok(Json(serde_json::json!({ "entries": entries })))
}

pub async fn redeem_credit_code(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'code' field".to_string()))?
        .trim()
        .replace('-', "");

    if code.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Code cannot be empty".to_string()));
    }

    let mut tx = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, amount_cents FROM credit_codes WHERE UPPER(code) = UPPER($1) AND redeemed_by IS NULL FOR UPDATE"
    )
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let (code_id, amount_cents) = match row {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "Invalid or already redeemed code".to_string(),
            ));
        }
    };

    sqlx::query("UPDATE credit_codes SET redeemed_by = $1, redeemed_at = NOW() WHERE id = $2")
        .bind(auth.user_id)
        .bind(code_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, user_id, delta_cents, entry_type, description)
         VALUES ($1, $2, $3, 'code_redemption', 'Redeemed credit code')",
    )
    .bind(org_id)
    .bind(auth.user_id)
    .bind(amount_cents)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to record ledger entry: {}", e),
        )
    })?;

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to compute balance: {}", e),
            )
        })?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    tracing::info!(
        "Credit code redeemed: user={}, code_id={}, +{} cents, new_balance={}",
        auth.user_id,
        code_id,
        amount_cents,
        new_balance
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "amount_cents": amount_cents,
        "new_balance": new_balance,
    })))
}

/// Atomically insert a credit_ledger row and return the derived balance.
pub async fn apply_credit(
    db: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    delta_cents: i64,
    entry_type: &str,
    description: &str,
    paddle_txn_id: Option<&str>,
    invoice_id: Option<Uuid>,
) -> Result<i64, String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin transaction: {}", e))?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, user_id, delta_cents, entry_type, description, paddle_transaction_id, invoice_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(org_id)
    .bind(user_id)
    .bind(delta_cents)
    .bind(entry_type)
    .bind(description)
    .bind(paddle_txn_id)
    .bind(invoice_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to insert credit_ledger: {}", e))?;

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id)
        .await
        .map_err(|e| format!("Failed to compute balance: {}", e))?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;

    Ok(new_balance)
}

// -- Auto top-up API endpoints --

#[derive(Deserialize)]
pub struct AutoTopupConfig {
    enabled: bool,
    amount_dollars: i32,
}

pub async fn get_auto_topup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let row = sqlx::query(
        "SELECT auto_topup_enabled, auto_topup_amount_dollars FROM billing_config WHERE organization_id = $1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let (enabled, amount) = match row {
        Some(r) => (
            r.get::<Option<bool>, _>("auto_topup_enabled")
                .unwrap_or(false),
            r.get::<Option<i32>, _>("auto_topup_amount_dollars")
                .unwrap_or(0),
        ),
        None => (false, 0),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "amount_dollars": amount,
    })))
}

pub async fn put_auto_topup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<AutoTopupConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if req.amount_dollars < 0 || req.amount_dollars > 10_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Auto top-up amount must be between $0 and $10,000".to_string(),
        ));
    }
    if req.enabled && req.amount_dollars < 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Auto top-up target must be at least $10".to_string(),
        ));
    }

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Verify user has an active payment method (required for auto-topup)
    if req.enabled {
        let payment_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true",
        )
        .bind(org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

        if payment_count == 0 {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                "An active payment method is required to enable auto top-up".to_string(),
            ));
        }
    }

    sqlx::query(
        "INSERT INTO billing_config (organization_id, auto_topup_enabled, auto_topup_amount_dollars)
         VALUES ($1, $2, $3)
         ON CONFLICT (organization_id) DO UPDATE SET
             auto_topup_enabled = $2,
             auto_topup_amount_dollars = $3"
    )
    .bind(org_id)
    .bind(req.enabled)
    .bind(req.amount_dollars)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    Ok(Json(serde_json::json!({
        "enabled": req.enabled,
        "amount_dollars": req.amount_dollars,
    })))
}

#[cfg(test)]
mod tests {
    use super::{
        extract_paddle_payment_method_id, transaction_contains_price_id,
        validate_paddle_setup_transaction,
    };

    fn sample_transaction() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "status": "completed",
                "collection_mode": "automatic",
                "customer_id": "ctm_123",
                "customer": {
                    "email": "user@example.com"
                },
                "items": [
                    {
                        "price": {
                            "id": "pri_setup"
                        }
                    }
                ],
                "details": {
                    "line_items": []
                },
                "payments": [
                    {
                        "payment_method_id": "paymtd_123"
                    }
                ]
            }
        })
    }

    #[test]
    fn extracts_payment_method_id_from_transaction() {
        let txn = sample_transaction();
        assert_eq!(
            extract_paddle_payment_method_id(&txn).as_deref(),
            Some("paymtd_123")
        );
    }

    #[test]
    fn finds_setup_price_in_transaction_items() {
        let txn = sample_transaction();
        assert!(transaction_contains_price_id(&txn, "pri_setup"));
        assert!(!transaction_contains_price_id(&txn, "pri_other"));
    }

    #[test]
    fn accepts_matching_existing_customer() {
        let txn = sample_transaction();
        let (customer_id, payment_method_id) =
            validate_paddle_setup_transaction(&txn, "pri_setup", Some("ctm_123"), None)
                .expect("transaction should validate");

        assert_eq!(customer_id, "ctm_123");
        assert_eq!(payment_method_id.as_deref(), Some("paymtd_123"));
    }

    #[test]
    fn accepts_first_time_setup_with_matching_email() {
        let txn = sample_transaction();
        let (customer_id, _) =
            validate_paddle_setup_transaction(&txn, "pri_setup", None, Some("USER@example.com"))
                .expect("transaction should validate");

        assert_eq!(customer_id, "ctm_123");
    }

    #[test]
    fn rejects_transaction_for_different_customer() {
        let txn = sample_transaction();
        let err = validate_paddle_setup_transaction(&txn, "pri_setup", Some("ctm_other"), None)
            .expect_err("transaction should be rejected");

        assert!(err.contains("does not belong to this account"));
    }

    #[test]
    fn rejects_transaction_without_setup_price() {
        let txn = serde_json::json!({
            "data": {
                "status": "completed",
                "collection_mode": "automatic",
                "customer_id": "ctm_123",
                "customer": {
                    "email": "user@example.com"
                },
                "items": [
                    {
                        "price": {
                            "id": "pri_other"
                        }
                    }
                ],
                "details": {
                    "line_items": []
                },
                "payments": []
            }
        });
        let err =
            validate_paddle_setup_transaction(&txn, "pri_setup", None, Some("user@example.com"))
                .expect_err("transaction should be rejected");

        assert!(err.contains("setup price"));
    }
}

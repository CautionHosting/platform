use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Datelike, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::{Executor, PgPool, Postgres, Row};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
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

#[derive(Debug, Deserialize)]
struct PaddleSavedPaymentMethodsResponse {
    data: Vec<PaddleSavedPaymentMethod>,
    #[serde(default)]
    meta: Option<PaddleListMeta>,
}

#[derive(Debug, Default, Deserialize)]
struct PaddleListMeta {
    #[serde(default)]
    pagination: Option<PaddlePagination>,
}

#[derive(Debug, Default, Deserialize)]
struct PaddlePagination {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PaddleSavedPaymentMethod {
    id: String,
    #[serde(rename = "type")]
    payment_type: String,
    #[serde(default)]
    card: Option<PaddleSavedCard>,
    #[serde(default)]
    paypal: Option<PaddleSavedPayPal>,
}

impl PaddleSavedPaymentMethod {
    fn card_last4(&self) -> Option<&str> {
        self.card.as_ref().and_then(|card| card.last4.as_deref())
    }

    fn card_brand(&self) -> Option<&str> {
        self.card.as_ref().and_then(|card| {
            card.brand
                .as_deref()
                .or(card.card_type.as_deref())
                .or(card.bin_type.as_deref())
        })
    }

    fn paypal_email(&self) -> Option<&str> {
        self.paypal
            .as_ref()
            .and_then(|paypal| paypal.email.as_deref())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct PaddleSavedCard {
    #[serde(default)]
    last4: Option<String>,
    #[serde(default, rename = "type")]
    card_type: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    bin_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PaddleSavedPayPal {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LocalPaymentMethodRow {
    id: Uuid,
    paddle_payment_method_id: Option<String>,
    is_primary: bool,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct CreditPackage {
    pub(crate) purchase_cents: i64,
    pub(crate) credit_cents: i64,
    pub(crate) bonus_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) paddle_price_id: Option<String>,
}

const PADDLE_CHECKOUT_BINDING_CONTEXT: &str = "paddle_setup_checkout_v1";
const PADDLE_CHECKOUT_BINDING_MAX_AGE_SECS: i64 = 3600;
const PAYMENT_METHOD_SYNC_TTL_SECS: i64 = 30;
const MIN_CUSTOM_CREDIT_PURCHASE_CENTS: i64 = 1_000;

type HmacSha256 = Hmac<Sha256>;

// Credit package base amounts (purchase_cents). Bonus percentages come from prices.json.
const CREDIT_PACKAGE_BASES: &[(i64, &str)] =
    &[(100_000, "1000"), (500_000, "5000"), (1_000_000, "10000")];

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

async fn list_paddle_saved_payment_methods(
    api_url: &str,
    api_key: &str,
    customer_id: &str,
) -> Result<Vec<PaddleSavedPaymentMethod>, String> {
    let client = reqwest::Client::new();
    let mut url = format!(
        "{}/customers/{}/payment-methods?per_page=200",
        api_url, customer_id
    );
    let mut methods = Vec::new();

    loop {
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| format!("Paddle API error: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let retry_after = paddle_retry_after_seconds(resp.headers());
            let body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(match retry_after {
                    Some(seconds) => format!(
                        "Paddle API rate limited this server IP. Retry after {} seconds.",
                        seconds
                    ),
                    None => "Paddle API rate limited this server IP. Retry after the delay in the Retry-After header.".to_string(),
                });
            }
            if body.is_empty() {
                return Err(format!("Paddle API returned {}", status));
            }
            return Err(format!("Paddle API returned {}: {}", status, body));
        }

        let page: PaddleSavedPaymentMethodsResponse = resp
            .json()
            .await
            .map_err(|e| format!("Parse error: {}", e))?;

        let next = page
            .meta
            .and_then(|meta| meta.pagination)
            .and_then(|pagination| pagination.next);
        methods.extend(page.data);

        let Some(next_url) = next else {
            break;
        };
        url = next_url;
    }

    Ok(methods)
}

fn paddle_retry_after_seconds(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

async fn sync_payment_methods_from_paddle(
    db: &PgPool,
    api_url: &str,
    api_key: &str,
    org_id: Uuid,
    customer_id: &str,
) -> Result<(), (StatusCode, String)> {
    let paddle_methods = list_paddle_saved_payment_methods(api_url, api_key, customer_id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to list Paddle payment methods: {}", e),
            )
        })?;

    let mut tx = db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let local_rows: Vec<LocalPaymentMethodRow> = sqlx::query_as(
        "SELECT id, paddle_payment_method_id, is_primary
         FROM payment_methods
         WHERE organization_id = $1
         ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let mut local_by_paddle_id: HashMap<String, LocalPaymentMethodRow> = HashMap::new();
    let mut duplicate_local_ids = Vec::new();
    for row in &local_rows {
        if let Some(payment_method_id) = row.paddle_payment_method_id.as_ref() {
            if local_by_paddle_id.contains_key(payment_method_id) {
                duplicate_local_ids.push(row.id);
            } else {
                local_by_paddle_id.insert(payment_method_id.clone(), row.clone());
            }
        }
    }
    let remote_ids: HashSet<&str> = paddle_methods
        .iter()
        .map(|method| method.id.as_str())
        .collect();

    for duplicate_id in duplicate_local_ids {
        sqlx::query(
            "UPDATE payment_methods
             SET is_active = false, is_primary = false
             WHERE id = $1",
        )
        .bind(duplicate_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
    }

    for method in &paddle_methods {
        let last4 = method.card_last4();
        let card_brand = method.card_brand();
        let email = method.paypal_email();

        if let Some(existing) = local_by_paddle_id.get(&method.id) {
            sqlx::query(
                "UPDATE payment_methods
                 SET payment_type = $2,
                     last4 = $3,
                     card_brand = $4,
                     email = $5,
                     is_active = true
                 WHERE id = $1",
            )
            .bind(existing.id)
            .bind(&method.payment_type)
            .bind(last4)
            .bind(card_brand)
            .bind(email)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?;
        } else {
            let should_be_primary = local_rows.is_empty()
                || !local_rows.iter().any(|row| row.is_primary) && paddle_methods.len() == 1;
            sqlx::query(
                "INSERT INTO payment_methods (
                    id,
                    organization_id,
                    payment_type,
                    provider_token,
                    paddle_payment_method_id,
                    last4,
                    card_brand,
                    email,
                    is_active,
                    is_primary,
                    created_at
                 )
                 VALUES ($1, $2, $3, '', $4, $5, $6, $7, true, $8, NOW())",
            )
            .bind(Uuid::new_v4())
            .bind(org_id)
            .bind(&method.payment_type)
            .bind(&method.id)
            .bind(last4)
            .bind(card_brand)
            .bind(email)
            .bind(should_be_primary)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?;
        }
    }

    for row in &local_rows {
        if let Some(payment_method_id) = row.paddle_payment_method_id.as_deref() {
            if !remote_ids.contains(payment_method_id) {
                sqlx::query(
                    "UPDATE payment_methods
                     SET is_active = false, is_primary = false
                     WHERE id = $1",
                )
                .bind(row.id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Database error: {}", e),
                    )
                })?;
            }
        }
    }

    let active_primary_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM payment_methods
         WHERE organization_id = $1 AND is_active = true AND is_primary = true",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    if active_primary_count == 0 {
        sqlx::query(
            "UPDATE payment_methods
             SET is_primary = true
             WHERE id = (
                SELECT id
                FROM payment_methods
                WHERE organization_id = $1 AND is_active = true
                ORDER BY created_at DESC
                LIMIT 1
             )",
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;
    }

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    Ok(())
}

async fn should_sync_payment_methods(
    db: &PgPool,
    org_id: Uuid,
) -> Result<bool, (StatusCode, String)> {
    let last_updated: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
        "SELECT MAX(updated_at) FROM payment_methods WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let Some(last_updated) = last_updated else {
        return Ok(true);
    };

    Ok(Utc::now()
        .naive_utc()
        .signed_duration_since(last_updated)
        .num_seconds()
        >= PAYMENT_METHOD_SYNC_TTL_SECS)
}

/// Get all active payment methods
pub async fn get_payment_methods(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

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

    if let (Some(customer_id), Some(api_key)) = (
        paddle_customer_id.as_deref(),
        state.paddle_api_key.as_deref(),
    ) {
        if !state.paddle_api_url.is_empty()
            && should_sync_payment_methods(&state.db, org_id).await?
        {
            if let Err((status, err)) = sync_payment_methods_from_paddle(
                &state.db,
                &state.paddle_api_url,
                api_key,
                org_id,
                customer_id,
            )
            .await
            {
                tracing::warn!(
                    "Failed to sync Paddle payment methods for org {} (status {}): {}",
                    org_id,
                    status,
                    err
                );
            }
        }
    }

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
    let method: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT is_primary, paddle_payment_method_id
         FROM payment_methods
         WHERE id = $1 AND organization_id = $2 AND is_active = true",
    )
    .bind(method_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let Some((was_primary, paddle_payment_method_id)) = method else {
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

    if let (Some(customer_id), Some(api_key), Some(payment_method_id)) = (
        sqlx::query_scalar::<_, Option<String>>(
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
        .flatten(),
        state.paddle_api_key.as_deref(),
        paddle_payment_method_id.as_deref(),
    ) {
        let client = reqwest::Client::new();
        let response = client
            .delete(format!(
                "{}/customers/{}/payment-methods/{}",
                state.paddle_api_url, customer_id, payment_method_id
            ))
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to delete payment method in Paddle: {}", e),
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_default();
            tracing::warn!(
                "Failed to delete Paddle payment method {} for org {}: {} - {}",
                payment_method_id,
                org_id,
                status,
                err_body
            );
            return Err((
                StatusCode::CONFLICT,
                "Paddle could not remove this payment method. It may still be tied to an active billing agreement.".to_string(),
            ));
        }
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

    let customer_auth_token = if let (Some(customer_id), Some(api_key)) = (
        paddle_customer_id.as_deref(),
        state.paddle_api_key.as_deref(),
    ) {
        if state.paddle_api_url.is_empty() {
            None
        } else {
            match generate_paddle_customer_auth_token(&state.paddle_api_url, api_key, customer_id)
                .await
            {
                Ok(token) => Some(token),
                Err(err) => {
                    tracing::warn!(
                        "Failed to generate Paddle customer auth token for org {} and customer {}: {}",
                        org_id,
                        customer_id,
                        err
                    );
                    None
                }
            }
        }
    } else {
        None
    };
    let checkout_custom_data = state
        .internal_service_secret
        .as_deref()
        .map(|secret| build_paddle_checkout_custom_data(secret, auth.user_id, org_id));

    Ok(Json(serde_json::json!({
        "client_token": client_token,
        "customer_auth_token": customer_auth_token,
        "checkout_custom_data": checkout_custom_data,
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

async fn upsert_local_payment_method(
    db: &PgPool,
    org_id: Uuid,
    transaction_id: &str,
    payment_method_id: Option<&str>,
    card_last4: Option<&str>,
    card_brand: Option<&str>,
) -> Result<(), sqlx::Error> {
    let Some(payment_method_id) = payment_method_id.filter(|value| !value.is_empty()) else {
        return Ok(());
    };

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true",
    )
    .bind(org_id)
    .fetch_one(db)
    .await?;
    let should_be_primary = active_count == 0;

    let existing_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id
         FROM payment_methods
         WHERE organization_id = $1 AND paddle_payment_method_id = $2
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(org_id)
    .bind(payment_method_id)
    .fetch_optional(db)
    .await?;

    if let Some(existing_id) = existing_id {
        sqlx::query(
            "UPDATE payment_methods
             SET payment_type = 'card',
                 provider_token = $2,
                 last4 = $3,
                 card_brand = $4,
                 is_active = true,
                 is_primary = CASE WHEN $5 THEN true ELSE is_primary END
             WHERE id = $1",
        )
        .bind(existing_id)
        .bind(transaction_id)
        .bind(card_last4)
        .bind(card_brand)
        .bind(should_be_primary)
        .execute(db)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO payment_methods (id, organization_id, payment_type, provider_token, paddle_payment_method_id, last4, card_brand, is_active, is_primary, created_at)
             VALUES ($1, $2, 'card', $3, $4, $5, $6, true, $7, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(org_id)
        .bind(transaction_id)
        .bind(payment_method_id)
        .bind(card_last4)
        .bind(card_brand)
        .bind(should_be_primary)
        .execute(db)
        .await?;
    }

    Ok(())
}

fn is_completed_paddle_transaction_status(status: &str) -> bool {
    matches!(status, "completed" | "paid" | "billed")
}

fn is_settled_credit_purchase_status(status: &str) -> bool {
    matches!(status, "completed" | "paid")
}

fn is_failed_credit_purchase_status(status: &str) -> bool {
    matches!(status, "past_due" | "canceled")
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

fn paddle_checkout_binding_payload(user_id: Uuid, org_id: Uuid, issued_at: i64) -> String {
    format!(
        "{}:{}:{}:{}",
        PADDLE_CHECKOUT_BINDING_CONTEXT, user_id, org_id, issued_at
    )
}

fn sign_paddle_checkout_binding(
    secret: &str,
    user_id: Uuid,
    org_id: Uuid,
    issued_at: i64,
) -> String {
    let payload = paddle_checkout_binding_payload(user_id, org_id, issued_at);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn build_paddle_checkout_custom_data(
    secret: &str,
    user_id: Uuid,
    org_id: Uuid,
) -> serde_json::Value {
    let issued_at = Utc::now().timestamp();
    serde_json::json!({
        "caution_checkout_user_id": user_id.to_string(),
        "caution_checkout_org_id": org_id.to_string(),
        "caution_checkout_issued_at": issued_at,
        "caution_checkout_sig": sign_paddle_checkout_binding(secret, user_id, org_id, issued_at),
    })
}

fn validate_paddle_checkout_binding(
    txn: &serde_json::Value,
    secret: &str,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<(), String> {
    let custom_data = txn["data"]["custom_data"]
        .as_object()
        .ok_or_else(|| "Transaction is not bound to this account".to_string())?;
    let txn_user_id = custom_data
        .get("caution_checkout_user_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Transaction is not bound to this account".to_string())?;
    let txn_org_id = custom_data
        .get("caution_checkout_org_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Transaction is not bound to this account".to_string())?;
    let issued_at = custom_data
        .get("caution_checkout_issued_at")
        .and_then(|value| value.as_i64())
        .ok_or_else(|| "Transaction is not bound to this account".to_string())?;
    let sig_hex = custom_data
        .get("caution_checkout_sig")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "Transaction is not bound to this account".to_string())?;

    if txn_user_id != user_id.to_string() || txn_org_id != org_id.to_string() {
        return Err("Transaction does not belong to this account".to_string());
    }

    let now = Utc::now().timestamp();
    if issued_at > now + 300 || now - issued_at > PADDLE_CHECKOUT_BINDING_MAX_AGE_SECS {
        return Err("Transaction checkout has expired. Please try again.".to_string());
    }

    let sig_bytes =
        hex::decode(sig_hex).map_err(|_| "Transaction checkout binding is invalid".to_string())?;
    let payload = paddle_checkout_binding_payload(user_id, org_id, issued_at);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig_bytes)
        .map_err(|_| "Transaction checkout binding is invalid".to_string())
}

fn validate_paddle_setup_transaction(
    txn: &serde_json::Value,
    expected_setup_price_id: &str,
    expected_customer_id: Option<&str>,
    expected_customer_email: Option<&str>,
    allow_checkout_binding: bool,
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
    } else if let Some(expected_customer_email) = expected_customer_email {
        let txn_customer_email = txn["data"]["customer"]["email"]
            .as_str()
            .ok_or_else(|| "Transaction customer email is unavailable".to_string())?;
        if !txn_customer_email.eq_ignore_ascii_case(expected_customer_email) {
            return Err("Transaction does not belong to this account".to_string());
        }
    } else if !allow_checkout_binding {
        return Err(
            "No billing customer, account email, or valid checkout binding on file".to_string(),
        );
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
    let allow_checkout_binding =
        if existing_paddle_customer_id.is_none() && user_email.as_deref().is_none() {
            let secret = state.internal_service_secret.as_deref().ok_or_else(|| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Checkout binding is unavailable. Contact support.".to_string(),
                )
            })?;
            validate_paddle_checkout_binding(&txn, secret, auth.user_id, org_id)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            true
        } else {
            false
        };

    let (customer_id, paddle_payment_method_id) = validate_paddle_setup_transaction(
        &txn,
        setup_price_id,
        existing_paddle_customer_id.as_deref(),
        user_email.as_deref(),
        allow_checkout_binding,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    upsert_local_payment_method(
        &state.db,
        org_id,
        &req.transaction_id,
        paddle_payment_method_id.as_deref(),
        req.card_last4.as_deref(),
        req.card_brand.as_deref(),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

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
        let status = resp.status();
        let retry_after = paddle_retry_after_seconds(resp.headers());
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(match retry_after {
                Some(seconds) => format!(
                    "Paddle API rate limited this server IP. Retry after {} seconds.",
                    seconds
                ),
                None => {
                    "Paddle API rate limited this server IP. Retry after the delay in the Retry-After header.".to_string()
                }
            });
        }
        if body.is_empty() {
            return Err(format!("Paddle API returned {}", status));
        }
        return Err(format!("Paddle API returned {}: {}", status, body));
    }

    resp.json().await.map_err(|e| format!("Parse error: {}", e))
}

async fn generate_paddle_customer_auth_token(
    api_url: &str,
    api_key: &str,
    customer_id: &str,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/customers/{}/auth-token", api_url, customer_id))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("Paddle API error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let retry_after = paddle_retry_after_seconds(resp.headers());
        let body = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(match retry_after {
                Some(seconds) => format!(
                    "Paddle API rate limited this server IP. Retry after {} seconds.",
                    seconds
                ),
                None => {
                    "Paddle API rate limited this server IP. Retry after the delay in the Retry-After header.".to_string()
                }
            });
        }
        if body.is_empty() {
            return Err(format!("Paddle API returned {}", status));
        }
        return Err(format!("Paddle API returned {}: {}", status, body));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Parse error: {}", e))?;
    body["data"]["customer_auth_token"]
        .as_str()
        .map(|token| token.to_string())
        .ok_or_else(|| "No customer_auth_token in response".to_string())
}

fn build_credit_purchase_custom_data(
    org_id: Uuid,
    user_id: Uuid,
    purchase: &ResolvedCreditPurchase,
) -> serde_json::Value {
    serde_json::json!({
        "caution_credit_purchase": true,
        "caution_credit_purchase_org_id": org_id.to_string(),
        "caution_credit_purchase_user_id": user_id.to_string(),
        "caution_credit_purchase_purchase_cents": purchase.purchase_cents,
        "caution_credit_purchase_credit_cents": purchase.credit_cents,
        "caution_credit_purchase_description": purchase.description,
    })
}

fn validate_credit_purchase_transaction(
    txn: &serde_json::Value,
    org_id: Uuid,
    user_id: Uuid,
    purchase: &ResolvedCreditPurchase,
) -> Result<(), String> {
    if let Some(expected_price_id) = purchase.price_id.as_deref() {
        if !transaction_contains_price_id(txn, expected_price_id) {
            return Err("Transaction does not match the selected credit package".to_string());
        }
    }

    let custom_data = txn["data"]["custom_data"]
        .as_object()
        .ok_or_else(|| "Transaction is missing credit purchase metadata".to_string())?;
    if custom_data
        .get("caution_credit_purchase")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return Err("Transaction is not a credit purchase".to_string());
    }

    let org_id_string = org_id.to_string();
    if custom_data
        .get("caution_credit_purchase_org_id")
        .and_then(|value| value.as_str())
        != Some(org_id_string.as_str())
    {
        return Err("Transaction does not belong to this account".to_string());
    }

    let user_id_string = user_id.to_string();
    if custom_data
        .get("caution_credit_purchase_user_id")
        .and_then(|value| value.as_str())
        != Some(user_id_string.as_str())
    {
        return Err("Transaction does not belong to this user".to_string());
    }

    if custom_data
        .get("caution_credit_purchase_purchase_cents")
        .and_then(|value| value.as_i64())
        != Some(purchase.purchase_cents)
    {
        return Err("Transaction amount does not match the requested credit purchase".to_string());
    }

    if custom_data
        .get("caution_credit_purchase_credit_cents")
        .and_then(|value| value.as_i64())
        != Some(purchase.credit_cents)
    {
        return Err("Transaction credit amount does not match the requested package".to_string());
    }

    Ok(())
}

fn build_credit_purchase_transaction_item(
    purchase: &ResolvedCreditPurchase,
) -> Result<serde_json::Value, (StatusCode, String)> {
    if let Some(price_id) = purchase.price_id.as_ref() {
        return Ok(serde_json::json!({
            "price_id": price_id,
            "quantity": 1,
        }));
    }

    Ok(serde_json::json!({
        "quantity": 1,
        "price": {
            "description": format!(
                "Custom prepaid credit purchase for {} credits",
                format_currency_amount(purchase.credit_cents)
            ),
            "name": format!("${} prepaid credits", format_currency_amount(purchase.credit_cents)),
            "unit_price": {
                "amount": purchase.purchase_cents.to_string(),
                "currency_code": "USD",
            },
            "product": {
                "name": "Caution prepaid credits",
                "tax_category": "standard",
                "description": "Prepaid usage credits for Caution",
            }
        }
    }))
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
                "purchase_display": format!("${}", format_currency_amount(pkg.purchase_cents)),
                "credit_display": format!("${}", format_currency_amount(pkg.credit_cents)),
                "paddle_price_id": pkg.paddle_price_id,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "packages": packages })))
}

#[derive(Deserialize)]
pub struct PurchaseCreditsRequest {
    /// Set by frontend after Paddle checkout completes
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(default)]
    package_index: Option<usize>,
    #[serde(default)]
    amount_cents: Option<i64>,
    #[serde(default)]
    payment_method_id: Option<String>,
    #[serde(default)]
    card_last4: Option<String>,
    #[serde(default)]
    card_brand: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedCreditPurchase {
    purchase_cents: i64,
    credit_cents: i64,
    price_id: Option<String>,
    description: String,
}

fn format_currency_amount(cents: i64) -> String {
    format!("{:.2}", cents as f64 / 100.0)
}

fn resolve_credit_purchase_request(
    req: &PurchaseCreditsRequest,
    credit_packages: &[CreditPackage],
    paddle_price_ids: &[Option<String>; 3],
) -> Result<ResolvedCreditPurchase, (StatusCode, String)> {
    match (req.package_index, req.amount_cents) {
        (Some(_), Some(_)) => Err((
            StatusCode::BAD_REQUEST,
            "Provide either package_index or amount_cents, not both".to_string(),
        )),
        (None, None) => Err((
            StatusCode::BAD_REQUEST,
            "package_index or amount_cents is required".to_string(),
        )),
        (Some(package_index), None) => {
            let pkg = credit_packages
                .get(package_index)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid package index".to_string()))?;

            Ok(ResolvedCreditPurchase {
                purchase_cents: pkg.purchase_cents,
                credit_cents: pkg.credit_cents,
                price_id: paddle_price_ids[package_index].clone(),
                description: format!(
                    "Credit purchase: ${} → ${} credits ({}% bonus)",
                    format_currency_amount(pkg.purchase_cents),
                    format_currency_amount(pkg.credit_cents),
                    pkg.bonus_percent,
                ),
            })
        }
        (None, Some(amount_cents)) => {
            if amount_cents < MIN_CUSTOM_CREDIT_PURCHASE_CENTS {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Custom credit purchase must be at least ${}",
                        format_currency_amount(MIN_CUSTOM_CREDIT_PURCHASE_CENTS)
                    ),
                ));
            }

            Ok(ResolvedCreditPurchase {
                purchase_cents: amount_cents,
                credit_cents: amount_cents,
                price_id: None,
                description: format!(
                    "Custom credit purchase: ${} → ${} credits",
                    format_currency_amount(amount_cents),
                    format_currency_amount(amount_cents),
                ),
            })
        }
    }
}

pub async fn purchase_credits(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PurchaseCreditsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let purchase =
        resolve_credit_purchase_request(&req, &credit_packages, &state.paddle_credits_price_ids)?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    if req.transaction_id.is_none() {
        let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Paddle API not configured".to_string(),
            )
        })?;
        let paddle_client_token = state.paddle_client_token.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Paddle checkout not configured".to_string(),
            )
        })?;

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

        let customer_auth_token = if let Some(customer_id) = paddle_customer_id.as_deref() {
            Some(
                generate_paddle_customer_auth_token(
                    &state.paddle_api_url,
                    paddle_api_key,
                    customer_id,
                )
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("Failed to generate Paddle customer auth token: {}", e),
                    )
                })?,
            )
        } else {
            None
        };

        let custom_data = build_credit_purchase_custom_data(org_id, auth.user_id, &purchase);
        let item = build_credit_purchase_transaction_item(&purchase)?;
        let mut body = serde_json::json!({
            "items": [item],
            "collection_mode": "automatic",
            "custom_data": custom_data,
        });
        if let Some(customer_id) = paddle_customer_id.as_deref() {
            body["customer_id"] = serde_json::json!(customer_id);
        }
        if purchase.price_id.is_none() {
            body["currency_code"] = serde_json::json!("USD");
        }

        let client = reqwest::Client::new();
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
            let retry_after = paddle_retry_after_seconds(response.headers());
            let err_body = response.text().await.unwrap_or_default();
            tracing::error!("Paddle transaction failed: {} - {}", status, err_body);
            return Err((
                StatusCode::BAD_GATEWAY,
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    match retry_after {
                        Some(seconds) => format!(
                            "Paddle payment failed: rate limited, retry after {} seconds",
                            seconds
                        ),
                        None => {
                            "Paddle payment failed: rate limited, retry after the Retry-After delay"
                                .to_string()
                        }
                    }
                } else {
                    format!("Paddle payment failed: {}", status)
                },
            ));
        }

        let resp: serde_json::Value = response.json().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Paddle response parse error: {}", e),
            )
        })?;

        let transaction_id = resp["data"]["id"]
            .as_str()
            .ok_or_else(|| {
                (
                    StatusCode::BAD_GATEWAY,
                    "Missing transaction ID in Paddle response".to_string(),
                )
            })?
            .to_string();

        tracing::info!(
            "Created Paddle transaction {} for credit purchase checkout ({} cents)",
            transaction_id,
            purchase.purchase_cents
        );

        return Ok(Json(serde_json::json!({
            "success": true,
            "requires_checkout": true,
            "transaction_id": transaction_id,
            "client_token": paddle_client_token,
            "customer_auth_token": customer_auth_token,
            "paddle_customer_id": paddle_customer_id,
        })));
    }

    let transaction_id = req.transaction_id.unwrap_or_default();
    let (transaction_status, verified_payment_method_id) = {
        let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Paddle API not configured".to_string(),
            )
        })?;

        let client = reqwest::Client::new();
        let verify_resp = client
            .get(format!(
                "{}/transactions/{}",
                state.paddle_api_url, transaction_id
            ))
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
                transaction_id,
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

        validate_credit_purchase_transaction(&verify_data, org_id, auth.user_id, &purchase)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

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
                    transaction_id,
                    txn_customer_id,
                    expected_cid
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Transaction does not belong to this account".to_string(),
                ));
            }
        } else {
            if txn_customer_id.is_empty() {
                tracing::warn!(
                    "Org {} has no paddle_customer_id on file and transaction {} has no customer_id",
                    org_id,
                    transaction_id
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    "No billing account on file".to_string(),
                ));
            }

            if let Err(e) = sqlx::query(
                "INSERT INTO billing_config (organization_id, paddle_customer_id)
                 VALUES ($1, $2)
                 ON CONFLICT (organization_id) DO UPDATE SET paddle_customer_id = $2",
            )
            .bind(org_id)
            .bind(txn_customer_id)
            .execute(&state.db)
            .await
            {
                tracing::error!(
                    "Failed to store paddle_customer_id {} for org {} after credit purchase {}: {}",
                    txn_customer_id,
                    org_id,
                    transaction_id,
                    e
                );
            } else {
                tracing::info!(
                    "Stored paddle_customer_id {} for org {} from credit purchase {}",
                    txn_customer_id,
                    org_id,
                    transaction_id
                );
            }
        }

        (
            verify_data["data"]["status"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            req.payment_method_id
                .clone()
                .or_else(|| extract_paddle_payment_method_id(&verify_data)),
        )
    };

    upsert_local_payment_method(
        &state.db,
        org_id,
        &transaction_id,
        verified_payment_method_id.as_deref(),
        req.card_last4.as_deref(),
        req.card_brand.as_deref(),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

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

    if is_failed_credit_purchase_status(&transaction_status) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!(
                "Transaction payment failed (status: {})",
                transaction_status
            ),
        ));
    }

    if !is_settled_credit_purchase_status(&transaction_status) {
        tracing::info!(
            "Credit purchase transaction {} is pending settlement with status {}",
            transaction_id,
            transaction_status
        );

        return Ok(Json(serde_json::json!({
            "success": true,
            "pending": true,
            "transaction_id": transaction_id,
            "transaction_status": transaction_status,
        })));
    }

    let new_balance = apply_credit(
        &state.db,
        org_id,
        auth.user_id,
        purchase.credit_cents,
        "purchase",
        &purchase.description,
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
        purchase.credit_cents,
        new_balance
    );

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
        build_paddle_checkout_custom_data, extract_paddle_payment_method_id,
        resolve_credit_purchase_request, transaction_contains_price_id,
        validate_credit_purchase_transaction, validate_paddle_checkout_binding,
        validate_paddle_setup_transaction, CreditPackage, PurchaseCreditsRequest,
    };
    use axum::http::StatusCode;
    use uuid::Uuid;

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

    fn sample_credit_packages() -> Vec<CreditPackage> {
        vec![
            CreditPackage {
                purchase_cents: 100_000,
                credit_cents: 102_500,
                bonus_percent: 2.5,
                paddle_price_id: Some("pri_1000".to_string()),
            },
            CreditPackage {
                purchase_cents: 500_000,
                credit_cents: 525_000,
                bonus_percent: 5.0,
                paddle_price_id: Some("pri_5000".to_string()),
            },
            CreditPackage {
                purchase_cents: 1_000_000,
                credit_cents: 1_100_000,
                bonus_percent: 10.0,
                paddle_price_id: Some("pri_10000".to_string()),
            },
        ]
    }

    fn sample_credit_price_ids() -> [Option<String>; 3] {
        [
            Some("pri_1000".to_string()),
            Some("pri_5000".to_string()),
            Some("pri_10000".to_string()),
        ]
    }

    fn sample_credit_purchase_transaction(
        org_id: Uuid,
        user_id: Uuid,
        purchase_cents: i64,
        credit_cents: i64,
        price_id: Option<&str>,
    ) -> serde_json::Value {
        let items = if let Some(price_id) = price_id {
            serde_json::json!([
                {
                    "price": {
                        "id": price_id
                    }
                }
            ])
        } else {
            serde_json::json!([
                {
                    "price": {
                        "type": "custom"
                    }
                }
            ])
        };
        serde_json::json!({
            "data": {
                "status": "completed",
                "collection_mode": "automatic",
                "customer_id": "ctm_123",
                "items": items,
                "details": {
                    "line_items": []
                },
                "custom_data": {
                    "caution_credit_purchase": true,
                    "caution_credit_purchase_org_id": org_id.to_string(),
                    "caution_credit_purchase_user_id": user_id.to_string(),
                    "caution_credit_purchase_purchase_cents": purchase_cents,
                    "caution_credit_purchase_credit_cents": credit_cents,
                    "caution_credit_purchase_description": "Credit purchase"
                }
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
    fn resolves_preset_credit_purchase_request() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: Some(1),
            amount_cents: None,
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let resolved = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect("preset package should resolve");

        assert_eq!(resolved.purchase_cents, 500_000);
        assert_eq!(resolved.credit_cents, 525_000);
        assert_eq!(resolved.price_id.as_deref(), Some("pri_5000"));
    }

    #[test]
    fn rejects_missing_credit_package_request() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: None,
            amount_cents: None,
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let err = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect_err("missing package should be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "package_index or amount_cents is required");
    }

    #[test]
    fn rejects_invalid_credit_package_index() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: Some(99),
            amount_cents: None,
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let err = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect_err("invalid package index should be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Invalid package index");
    }

    #[test]
    fn resolves_custom_credit_purchase_request() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: None,
            amount_cents: Some(1_234),
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let resolved = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect("custom amount should resolve");

        assert_eq!(resolved.purchase_cents, 1_234);
        assert_eq!(resolved.credit_cents, 1_234);
        assert!(resolved.price_id.is_none());
    }

    #[test]
    fn rejects_custom_credit_purchase_below_minimum() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: None,
            amount_cents: Some(999),
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let err = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect_err("custom amount should be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Custom credit purchase must be at least $10.00");
    }

    #[test]
    fn rejects_credit_purchase_request_with_package_and_amount() {
        let req = PurchaseCreditsRequest {
            transaction_id: None,
            package_index: Some(1),
            amount_cents: Some(2_000),
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };

        let err = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect_err("mixed request should be rejected");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1,
            "Provide either package_index or amount_cents, not both"
        );
    }

    #[test]
    fn validates_matching_credit_purchase_transaction() {
        let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let req = PurchaseCreditsRequest {
            transaction_id: Some("txn_123".to_string()),
            package_index: Some(1),
            amount_cents: None,
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };
        let purchase = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect("preset package should resolve");
        let txn = sample_credit_purchase_transaction(
            org_id,
            user_id,
            purchase.purchase_cents,
            purchase.credit_cents,
            Some("pri_5000"),
        );

        validate_credit_purchase_transaction(&txn, org_id, user_id, &purchase)
            .expect("transaction metadata should validate");
    }

    #[test]
    fn validates_matching_custom_credit_purchase_transaction() {
        let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let req = PurchaseCreditsRequest {
            transaction_id: Some("txn_123".to_string()),
            package_index: None,
            amount_cents: Some(1_500),
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };
        let purchase = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect("custom amount should resolve");
        let txn = sample_credit_purchase_transaction(
            org_id,
            user_id,
            purchase.purchase_cents,
            purchase.credit_cents,
            None,
        );

        validate_credit_purchase_transaction(&txn, org_id, user_id, &purchase)
            .expect("custom transaction metadata should validate");
    }

    #[test]
    fn rejects_credit_purchase_transaction_for_wrong_user() {
        let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let other_user_id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let req = PurchaseCreditsRequest {
            transaction_id: Some("txn_123".to_string()),
            package_index: Some(1),
            amount_cents: None,
            payment_method_id: None,
            card_last4: None,
            card_brand: None,
        };
        let purchase = resolve_credit_purchase_request(
            &req,
            &sample_credit_packages(),
            &sample_credit_price_ids(),
        )
        .expect("preset package should resolve");
        let txn = sample_credit_purchase_transaction(
            org_id,
            other_user_id,
            purchase.purchase_cents,
            purchase.credit_cents,
            Some("pri_5000"),
        );

        let err = validate_credit_purchase_transaction(&txn, org_id, user_id, &purchase)
            .expect_err("transaction metadata should be rejected");
        assert!(err.contains("does not belong to this user"));
    }

    #[test]
    fn accepts_matching_existing_customer() {
        let txn = sample_transaction();
        let (customer_id, payment_method_id) =
            validate_paddle_setup_transaction(&txn, "pri_setup", Some("ctm_123"), None, false)
                .expect("transaction should validate");

        assert_eq!(customer_id, "ctm_123");
        assert_eq!(payment_method_id.as_deref(), Some("paymtd_123"));
    }

    #[test]
    fn accepts_first_time_setup_with_matching_email() {
        let txn = sample_transaction();
        let (customer_id, _) = validate_paddle_setup_transaction(
            &txn,
            "pri_setup",
            None,
            Some("USER@example.com"),
            false,
        )
        .expect("transaction should validate");

        assert_eq!(customer_id, "ctm_123");
    }

    #[test]
    fn accepts_first_time_setup_with_valid_checkout_binding() {
        let user_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let mut txn = sample_transaction();
        txn["data"]["custom_data"] = build_paddle_checkout_custom_data("secret", user_id, org_id);

        validate_paddle_checkout_binding(&txn, "secret", user_id, org_id)
            .expect("checkout binding should validate");

        let (customer_id, _) =
            validate_paddle_setup_transaction(&txn, "pri_setup", None, None, true)
                .expect("transaction should validate");

        assert_eq!(customer_id, "ctm_123");
    }

    #[test]
    fn rejects_transaction_for_different_customer() {
        let txn = sample_transaction();
        let err =
            validate_paddle_setup_transaction(&txn, "pri_setup", Some("ctm_other"), None, false)
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
        let err = validate_paddle_setup_transaction(
            &txn,
            "pri_setup",
            None,
            Some("user@example.com"),
            false,
        )
        .expect_err("transaction should be rejected");

        assert!(err.contains("setup price"));
    }
}

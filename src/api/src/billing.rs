use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Datelike, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::{Executor, PgPool, Postgres};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use uuid::Uuid;

use crate::{AppState, AuthContext, PricingConfig, get_user_primary_org};

/// A `payment_methods` row returned to the payment-methods listing handler.
type PaymentMethodRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
);

/// A `credit_ledger` row with a running balance, returned to the ledger listing handler.
type CreditLedgerRow = (
    Uuid,
    i64,
    i64,
    String,
    String,
    Option<String>,
    DateTime<Utc>,
);

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
        "r6i.xlarge" => 0.252,
        "r6i.2xlarge" => 0.504,
        "r6i.4xlarge" => 1.008,
        "r6i.8xlarge" => 2.016,
        "r6i.12xlarge" => 3.024,
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
    application_id: Option<Uuid>,
    resource_id: String,
    resource_name: String,
    resource_type: String,
    region: Option<String>,
    last_recorded_at: DateTime<Utc>,
    quantity: f64,
    unit: String,
    rate: f64,
    cost_cents: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct SubscriptionSpendRow {
    subscription_id: Uuid,
    tier: String,
    quantity: f64,
    rate: f64,
    cost_cents: i64,
    future_cost: f64,
}

#[derive(Debug, sqlx::FromRow)]
struct ActiveRunnerProjectionRow {
    resource_id: String,
    instance_type: Option<String>,
    last_billed_at: DateTime<Utc>,
    latest_rate: Option<f64>,
}

fn usage_row_id(row: &BillingUsageRow) -> String {
    let owner = row
        .application_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| row.resource_id.clone());
    format!(
        "usage:{owner}:{}:{}:{}:{}:{}:{:.10}",
        row.resource_id,
        row.resource_name,
        row.resource_type,
        row.unit,
        row.region.as_deref().unwrap_or(""),
        row.rate,
    )
}

fn projected_runner_cost(
    last_billed_at: DateTime<Utc>,
    month_start: DateTime<Utc>,
    month_end: DateTime<Utc>,
    hourly_rate: f64,
) -> f64 {
    let projection_start = last_billed_at.max(month_start);
    let seconds = (month_end - projection_start).num_seconds().max(0) as f64;
    seconds / 3600.0 * hourly_rate
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

/// Failure modes for [`get_ledger_balance_cents`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetLedgerBalanceCentsError {
    #[error("could not read credit ledger balance [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn get_ledger_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> Result<i64, GetLedgerBalanceCentsError>
where
    E: Executor<'e, Database = Postgres>,
{
    use GetLedgerBalanceCentsErrorCtx as Ctx;

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
    .with_context(Ctx::query())
}

/// Failure modes for [`get_debit_balance_cents`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetDebitBalanceCentsError {
    #[error("could not read debit ledger balance [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn get_debit_balance_cents<'e, E>(
    executor: E,
    organization_id: Uuid,
) -> Result<i64, GetDebitBalanceCentsError>
where
    E: Executor<'e, Database = Postgres>,
{
    use GetDebitBalanceCentsErrorCtx as Ctx;

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
    .with_context(Ctx::query())
}

/// Failure modes for [`get_billing_usage`]. Every failure carries a source.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetBillingUsageError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetBillingUsageError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetBillingUsageError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetBillingUsageError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_billing_usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetBillingUsageError> {
    use GetBillingUsageErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let now = chrono::Utc::now();

    // Calculate billing period (first of current month to end of month)
    let first_of_month_naive = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap();
    let first_of_month_dt = first_of_month_naive.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let next_month_naive = if now.month() == 12 {
        chrono::NaiveDate::from_ymd_opt(now.year() + 1, 1, 1).unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(now.year(), now.month() + 1, 1).unwrap()
    };
    let next_month_dt = next_month_naive.and_hms_opt(0, 0, 0).unwrap().and_utc();

    let lifetime_debits_cents = get_debit_balance_cents(&state.db, org_id)
        .await
        .with_context(Ctx::database())?;

    let usage_rows: Vec<BillingUsageRow> = sqlx::query_as(
        r#"
        WITH monthly_usage AS (
            SELECT
                ul.application_id,
                ul.resource_id,
                COALESCE(
                    NULLIF(cr.resource_name, ''),
                    NULLIF(ul.metadata->>'resource_name', ''),
                    ul.resource_id
                ) AS resource_name,
                ul.resource_type,
                COALESCE(
                    NULLIF(ul.metadata->>'region', ''),
                    NULLIF(cr.region, ''),
                    NULLIF(tr.region, '')
                ) AS region,
                ul.recorded_at,
                ul.unit,
                (
                    COALESCE(ul.base_unit_cost_usd, 0)
                    * (1 + COALESCE(ul.margin_percent, 0) / 100.0)
                )::double precision AS rate,
                ul.quantity::double precision AS quantity,
                ROUND((
                    ul.quantity
                    * COALESCE(ul.base_unit_cost_usd, 0)
                    * (1 + COALESCE(ul.margin_percent, 0) / 100.0)
                ) * 100)::bigint AS cost_cents
            FROM usage_ledger ul
            LEFT JOIN compute_resources cr
                ON cr.id = ul.application_id
               AND cr.organization_id = ul.organization_id
            LEFT JOIN tracked_resources tr
                ON tr.resource_id = ul.resource_id
               AND tr.organization_id = ul.organization_id
            WHERE ul.organization_id = $1
              AND ul.recorded_at >= $2
              AND ul.recorded_at < $3
              AND ul.resource_type NOT IN ('monthly_total', 'aws_cost_explorer')
        )
        SELECT
            application_id,
            resource_id,
            resource_name,
            resource_type,
            region,
            MAX(recorded_at) AS last_recorded_at,
            SUM(quantity)::double precision AS quantity,
            unit,
            rate,
            SUM(cost_cents)::bigint AS cost_cents
        FROM monthly_usage
        GROUP BY application_id, resource_id, resource_name, resource_type, region, unit, rate
        ORDER BY cost_cents DESC, resource_name ASC, resource_type ASC
        "#,
    )
    .bind(org_id)
    .bind(first_of_month_dt)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::database())?;

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
                ROUND(GREATEST(
                    EXTRACT(
                        EPOCH FROM
                            LEAST(COALESCE(sl.billing_period_end, $3), $3)
                            - GREATEST(sl.billing_period_start, $2)
                    ) / 3600.0
                    * sl.cost_hourly,
                    0
                ) * 100)::bigint AS cost_cents,
                CASE
                    WHEN sl.billing_period_end IS NULL
                     AND s.billing_source = 'legacy_credits'
                     AND s.status IN ('active', 'past_due')
                    THEN GREATEST(
                        EXTRACT(
                            EPOCH FROM $4 - GREATEST(sl.billing_period_start, $2, $3)
                        ) / 3600.0 * sl.cost_hourly,
                        0
                    )::double precision
                    ELSE 0::double precision
                END AS future_cost
            FROM subscription_ledger sl
            JOIN subscriptions s ON s.id = sl.subscription_id
            WHERE sl.organization_id = $1
              AND sl.billing_period_start < $4
              AND COALESCE(sl.billing_period_end, $4) > $2
        )
        SELECT
            subscription_id,
            tier,
            SUM(quantity)::double precision AS quantity,
            rate,
            SUM(cost_cents)::bigint AS cost_cents,
            SUM(future_cost)::double precision AS future_cost
        FROM monthly_subscription_spend
        GROUP BY subscription_id, tier, rate
        HAVING SUM(cost_cents) > 0 OR SUM(future_cost) > 0
        ORDER BY cost_cents DESC, tier ASC
        "#,
    )
    .bind(org_id)
    .bind(first_of_month_dt)
    .bind(now)
    .bind(next_month_dt)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::database())?;

    let active_runners: Vec<ActiveRunnerProjectionRow> = sqlx::query_as(
        r#"
        SELECT
            tr.resource_id,
            tr.instance_type,
            tr.last_billed_at,
            latest.latest_rate
        FROM tracked_resources tr
        LEFT JOIN LATERAL (
            SELECT
                (
                    ul.base_unit_cost_usd * (1 + ul.margin_percent / 100.0)
                )::double precision AS latest_rate
            FROM usage_ledger ul
            WHERE ul.organization_id = tr.organization_id
              AND ul.resource_id = tr.resource_id
              AND ul.resource_type = 'compute'
              AND ul.base_unit_cost_usd IS NOT NULL
              AND ul.margin_percent IS NOT NULL
            ORDER BY ul.recorded_at DESC, ul.created_at DESC, ul.id DESC
            LIMIT 1
        ) latest ON true
        WHERE tr.organization_id = $1
          AND tr.provider = 'aws'
          AND tr.status = 'running'
          AND COALESCE(tr.metadata->>'resource_type', '') <> 'builder'
          AND NOT (tr.metadata ? 'build_id')
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::database())?;

    let mut future_runner_costs = HashMap::new();
    for runner in active_runners {
        let hourly_rate = if let Some(rate) = runner.latest_rate {
            rate
        } else {
            let Some(instance_type) = runner.instance_type.as_deref() else {
                continue;
            };
            let Some(pricing) = state.pricing.instance_pricing(instance_type) else {
                continue;
            };
            pricing.unit_cost_usd()
        };
        future_runner_costs.insert(
            runner.resource_id,
            projected_runner_cost(
                runner.last_billed_at,
                first_of_month_dt,
                next_month_dt,
                hourly_rate,
            ),
        );
    }

    let usage_cost_cents: i64 = usage_rows.iter().map(|row| row.cost_cents).sum();
    let subscription_cost_cents: i64 = subscription_rows.iter().map(|row| row.cost_cents).sum();
    let total_cost = (usage_cost_cents + subscription_cost_cents) as f64 / 100.0;
    let future_runner_cost: f64 = future_runner_costs.values().copied().sum();
    let future_subscription_cost: f64 = subscription_rows.iter().map(|row| row.future_cost).sum();
    let total_projected = total_cost + future_runner_cost + future_subscription_cost;

    let latest_compute_record = usage_rows
        .iter()
        .filter(|row| row.resource_type == "compute")
        .fold(
            HashMap::<String, DateTime<Utc>>::new(),
            |mut latest, row| {
                latest
                    .entry(row.resource_id.clone())
                    .and_modify(|recorded_at| {
                        *recorded_at = (*recorded_at).max(row.last_recorded_at)
                    })
                    .or_insert(row.last_recorded_at);
                latest
            },
        );
    let mut items = Vec::new();
    let mut subscription_items = Vec::new();

    for row in usage_rows {
        let cost = row.cost_cents as f64 / 100.0;
        let future_cost = if row.resource_type == "compute"
            && latest_compute_record.get(&row.resource_id) == Some(&row.last_recorded_at)
        {
            future_runner_costs.remove(&row.resource_id).unwrap_or(0.0)
        } else {
            0.0
        };

        items.push(serde_json::json!({
            "id": usage_row_id(&row),
            "application_id": row.application_id,
            "resource_id": row.resource_id,
            "resource_name": row.resource_name,
            "resource_type": row.resource_type,
            "region": row.region,
            "last_recorded_at": row.last_recorded_at,
            "quantity": row.quantity,
            "unit": row.unit,
            "rate": row.rate,
            "cost": cost,
            "projected_cost": cost + future_cost,
        }));
    }

    for row in subscription_rows {
        let cost = row.cost_cents as f64 / 100.0;

        subscription_items.push(serde_json::json!({
            "id": format!("{}:{}:{:.6}", row.subscription_id, row.tier, row.rate),
            "subscription_id": row.subscription_id,
            "tier": row.tier,
            "resource_name": crate::subscriptions::tier_display_name(&row.tier),
            "resource_type": "subscription",
            "quantity": row.quantity,
            "unit": "hours",
            "rate": row.rate,
            "cost": cost,
            "projected_cost": cost + row.future_cost,
        }));
    }

    Ok(Json(serde_json::json!({
        "total_cost": total_cost,
        "lifetime_cost": lifetime_debits_cents as f64 / 100.0,
        "projected_cost": total_projected,
        "currency": "USD",
        "billing_period_start": first_of_month_naive.to_string(),
        "billing_period_end": next_month_naive.to_string(),
        "items": items,
        "subscription_items": subscription_items,
    })))
}

/// Failure modes for [`get_billing_invoices`]. Only the primary-organization
/// lookup can fail (the invoice read swallows errors and returns an empty list).
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetBillingInvoicesError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetBillingInvoicesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetBillingInvoicesError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
        };
        (status, body).into_response()
    }
}

/// Get billing invoices
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_billing_invoices(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetBillingInvoicesError> {
    use GetBillingInvoicesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

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

/// Failure modes for [`list_paddle_saved_payment_methods`]. All failures are
/// surfaced to a caller-side log; none reach an HTTP client.
#[derive(Debug, thiserror::Error, CtxError)]
enum ListPaddleSavedPaymentMethodsError {
    #[error("could not reach the Paddle API [{location}]")]
    Transport {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle rate limited this server IP [{location}]")]
    RateLimited { location: Location },

    #[error("Paddle returned an error status [{location}]")]
    ApiStatus { location: Location },

    #[error("could not parse the Paddle response [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn list_paddle_saved_payment_methods(
    api_url: &str,
    api_key: &str,
    customer_id: &str,
) -> Result<Vec<PaddleSavedPaymentMethod>, ListPaddleSavedPaymentMethodsError> {
    use ListPaddleSavedPaymentMethodsError as E;
    use ListPaddleSavedPaymentMethodsErrorCtx as Ctx;
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
            .with_context(Ctx::transport())?;

        if !resp.status().is_success() {
            let status = resp.status();
            let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS;
            let _body = resp.text().await.unwrap_or_default();
            return Err(if rate_limited {
                E::RateLimited {
                    location: std::panic::Location::caller(),
                }
            } else {
                E::ApiStatus {
                    location: std::panic::Location::caller(),
                }
            });
        }

        let page: PaddleSavedPaymentMethodsResponse =
            resp.json().await.with_context(Ctx::parse())?;

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

/// Failure modes for [`sync_payment_methods_from_paddle`]. All failures carry a
/// source; the caller logs them and never surfaces them to an HTTP client.
#[derive(Debug, thiserror::Error, CtxError)]
enum SyncPaymentMethodsFromPaddleError {
    #[error("could not list Paddle payment methods [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database operation failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn sync_payment_methods_from_paddle(
    db: &PgPool,
    api_url: &str,
    api_key: &str,
    org_id: Uuid,
    customer_id: &str,
) -> Result<(), SyncPaymentMethodsFromPaddleError> {
    use SyncPaymentMethodsFromPaddleErrorCtx as Ctx;

    let paddle_methods = list_paddle_saved_payment_methods(api_url, api_key, customer_id)
        .await
        .with_context(Ctx::list())?;

    let mut tx = db.begin().await.with_context(Ctx::database())?;

    let local_rows: Vec<LocalPaymentMethodRow> = sqlx::query_as(
        "SELECT id, paddle_payment_method_id, is_primary
         FROM payment_methods
         WHERE organization_id = $1
         ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await
    .with_context(Ctx::database())?;

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
        .with_context(Ctx::database())?;
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
            .with_context(Ctx::database())?;
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
            .with_context(Ctx::database())?;
        }
    }

    for row in &local_rows {
        if let Some(payment_method_id) = row.paddle_payment_method_id.as_deref()
            && !remote_ids.contains(payment_method_id)
        {
            sqlx::query(
                "UPDATE payment_methods
                     SET is_active = false, is_primary = false
                     WHERE id = $1",
            )
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .with_context(Ctx::database())?;
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
    .with_context(Ctx::database())?;

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
        .with_context(Ctx::database())?;
    }

    tx.commit().await.with_context(Ctx::database())?;

    Ok(())
}

/// Failure modes for [`should_sync_payment_methods`] (a single source-bearing
/// database failure).
#[derive(Debug, thiserror::Error, CtxError)]
enum ShouldSyncPaymentMethodsError {
    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn should_sync_payment_methods(
    db: &PgPool,
    org_id: Uuid,
) -> Result<bool, ShouldSyncPaymentMethodsError> {
    use ShouldSyncPaymentMethodsErrorCtx as Ctx;
    let last_updated: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
        "SELECT MAX(updated_at) FROM payment_methods WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_one(db)
    .await
    .with_context(Ctx::database())?;

    let Some(last_updated) = last_updated else {
        return Ok(true);
    };

    Ok(Utc::now()
        .naive_utc()
        .signed_duration_since(last_updated)
        .num_seconds()
        >= PAYMENT_METHOD_SYNC_TTL_SECS)
}

/// Failure modes for [`get_payment_methods`]. The payment-method sync is
/// best-effort (logged, never surfaced); only the org lookup and local reads reach
/// a client.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetPaymentMethodsError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetPaymentMethodsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetPaymentMethodsError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetPaymentMethodsError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Get all active payment methods
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_payment_methods(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetPaymentMethodsError> {
    use GetPaymentMethodsErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database())?
    .flatten();

    if let (Some(customer_id), Some(api_key)) = (
        paddle_customer_id.as_deref(),
        state.paddle_api_key.as_deref(),
    ) && !state.paddle_api_url.is_empty()
    {
        let should_sync = should_sync_payment_methods(&state.db, org_id)
            .await
            .with_context(Ctx::database())?;
        if should_sync
            && let Err(err) = sync_payment_methods_from_paddle(
                &state.db,
                &state.paddle_api_url,
                api_key,
                org_id,
                customer_id,
            )
            .await
        {
            tracing::warn!(org_id = %org_id, error = %err, "Failed to sync Paddle payment methods");
        }
    }

    let rows: Vec<PaymentMethodRow> = sqlx::query_as(
        "SELECT id, payment_type, last4, card_brand, email, is_primary
         FROM payment_methods
         WHERE organization_id = $1 AND is_active = true
         ORDER BY is_primary DESC, created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::database())?;

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

/// Failure modes for [`delete_payment_method`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeletePaymentMethodError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("payment method not found [{location}]")]
    NotFound { location: Location },

    #[error("cannot remove the last payment method [{location}]")]
    LastMethod { location: Location },

    #[error("could not reach the Paddle API [{location}]")]
    PaddleTransport {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle could not remove this payment method [{location}]")]
    PaddleAgreement { location: Location },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeletePaymentMethodError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeletePaymentMethodError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeletePaymentMethodError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Payment method not found")
            }
            DeletePaymentMethodError::LastMethod { .. } => (
                StatusCode::CONFLICT,
                "You must have at least one payment method on file. Add another payment method before removing this one.",
            ),
            DeletePaymentMethodError::PaddleTransport { .. } => {
                (StatusCode::BAD_GATEWAY, "failed to delete payment method")
            }
            DeletePaymentMethodError::PaddleAgreement { .. } => (
                StatusCode::CONFLICT,
                "Paddle could not remove this payment method. It may still be tied to an active billing agreement.",
            ),
            DeletePaymentMethodError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Delete a specific payment method by ID
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id, method_id = %method_id))]
pub async fn delete_payment_method(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(method_id): Path<Uuid>,
) -> Result<StatusCode, DeletePaymentMethodError> {
    use DeletePaymentMethodErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

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
    .with_context(Ctx::database())?;

    let Some((was_primary, paddle_payment_method_id)) = method else {
        tracing::warn!(method_id = %method_id, "payment method not found or no access");
        return Err(DeletePaymentMethodError::NotFound {
            location: std::panic::Location::caller(),
        });
    };

    // Block deletion if this is the last active payment method and org has running resources
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true",
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::database())?;

    if active_count <= 1 {
        return Err(DeletePaymentMethodError::LastMethod {
            location: std::panic::Location::caller(),
        });
    }

    if let (Some(customer_id), Some(api_key), Some(payment_method_id)) = (
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
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
            .with_context(Ctx::paddle_transport())?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_default();
            tracing::warn!(
                payment_method_id, org_id = %org_id, status = %status, body = %err_body,
                "Failed to delete Paddle payment method"
            );
            return Err(DeletePaymentMethodError::PaddleAgreement {
                location: std::panic::Location::caller(),
            });
        }
    }

    // Soft-delete
    sqlx::query("UPDATE payment_methods SET is_active = false, is_primary = false WHERE id = $1")
        .bind(method_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::database())?;

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
        .with_context(Ctx::database())?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Failure modes for [`set_primary_payment_method`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum SetPrimaryPaymentMethodError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("payment method not found [{location}]")]
    NotFound { location: Location },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SetPrimaryPaymentMethodError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            SetPrimaryPaymentMethodError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            SetPrimaryPaymentMethodError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Payment method not found")
            }
            SetPrimaryPaymentMethodError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Set a payment method as primary
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id, method_id = %method_id))]
pub async fn set_primary_payment_method(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(method_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, SetPrimaryPaymentMethodError> {
    use SetPrimaryPaymentMethodErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    // Verify the method belongs to this org
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM payment_methods WHERE id = $1 AND organization_id = $2 AND is_active = true"
    )
    .bind(method_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await


    .with_context(Ctx::database())?;

    if exists.is_none() {
        return Err(SetPrimaryPaymentMethodError::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    // Atomically swap primary in a transaction
    let mut tx = state.db.begin().await.with_context(Ctx::database())?;

    sqlx::query(
        "UPDATE payment_methods SET is_primary = false WHERE organization_id = $1 AND is_active = true"
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await


    .with_context(Ctx::database())?;

    sqlx::query("UPDATE payment_methods SET is_primary = true WHERE id = $1")
        .bind(method_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::database())?;

    tx.commit().await.with_context(Ctx::database())?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Failure modes for [`get_paddle_client_token`]. Token generation is best-effort
/// (logged and defaulted to `None`); only the config gate, org lookup, and the
/// customer read reach a client.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetPaddleClientTokenError {
    #[error("Paddle is not configured [{location}]")]
    NotConfigured { location: Location },

    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetPaddleClientTokenError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetPaddleClientTokenError::NotConfigured { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "Paddle is not configured")
            }
            GetPaddleClientTokenError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetPaddleClientTokenError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Get Paddle client token and customer ID for frontend Paddle.js initialization
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_paddle_client_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetPaddleClientTokenError> {
    use GetPaddleClientTokenErrorCtx as Ctx;

    let client_token = state.paddle_client_token.as_ref().ok_or_else(|| {
        tracing::warn!("Paddle is not configured");
        GetPaddleClientTokenError::NotConfigured {
            location: std::panic::Location::caller(),
        }
    })?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    // Get the org's Paddle customer ID if one exists
    let paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database())?
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
                    tracing::warn!(org_id = %org_id, customer_id, error = %err, "Failed to generate Paddle customer auth token");
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

#[tracing::instrument(skip_all, err)]
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

/// Categories of checkout-binding validation failure (internal only; the
/// consuming handler renders a fixed generic body).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ValidatePaddleCheckoutBindingErrorKind {
    NotBound,
    WrongAccount,
    Expired,
    InvalidSig,
    HexDecode,
}

/// Failure modes for [`validate_paddle_checkout_binding`] (source-less domain
/// failures; callers box this error as a `#[source]`).
#[derive(Debug, thiserror::Error)]
#[error("invalid checkout binding ({kind:?}) [{location}]")]
struct ValidatePaddleCheckoutBindingError {
    kind: ValidatePaddleCheckoutBindingErrorKind,
    location: Location,
}

#[tracing::instrument(skip_all, err)]
fn validate_paddle_checkout_binding(
    txn: &serde_json::Value,
    secret: &str,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<(), ValidatePaddleCheckoutBindingError> {
    use ValidatePaddleCheckoutBindingErrorKind as Kind;
    let not_bound = |kind| ValidatePaddleCheckoutBindingError {
        kind,
        location: std::panic::Location::caller(),
    };

    let custom_data = txn["data"]["custom_data"]
        .as_object()
        .ok_or_else(|| not_bound(Kind::NotBound))?;
    let txn_user_id = custom_data
        .get("caution_checkout_user_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| not_bound(Kind::NotBound))?;
    let txn_org_id = custom_data
        .get("caution_checkout_org_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| not_bound(Kind::NotBound))?;
    let issued_at = custom_data
        .get("caution_checkout_issued_at")
        .and_then(|value| value.as_i64())
        .ok_or_else(|| not_bound(Kind::NotBound))?;
    let sig_hex = custom_data
        .get("caution_checkout_sig")
        .and_then(|value| value.as_str())
        .ok_or_else(|| not_bound(Kind::NotBound))?;

    if txn_user_id != user_id.to_string() || txn_org_id != org_id.to_string() {
        return Err(not_bound(Kind::WrongAccount));
    }

    let now = Utc::now().timestamp();
    if issued_at > now + 300 || now - issued_at > PADDLE_CHECKOUT_BINDING_MAX_AGE_SECS {
        return Err(not_bound(Kind::Expired));
    }

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(bytes) => bytes,
        Err(_source) => return Err(not_bound(Kind::HexDecode)),
    };
    let payload = paddle_checkout_binding_payload(user_id, org_id, issued_at);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    match mac.verify_slice(&sig_bytes) {
        Ok(()) => Ok(()),
        Err(_source) => Err(not_bound(Kind::InvalidSig)),
    }
}

/// Categories of setup-transaction validation failure (internal only; the
/// consuming handler renders a fixed generic body).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ValidatePaddleSetupTransactionErrorKind {
    NotCompleted,
    NotAutomatic,
    WrongPrice,
    NoCustomerId,
    WrongAccount,
    CustomerEmailUnavailable,
    NoBinding,
}

/// Failure modes for [`validate_paddle_setup_transaction`] (source-less domain
/// failures; callers box this error as a `#[source]`).
#[derive(Debug, thiserror::Error)]
#[error("invalid setup transaction ({kind:?}) [{location}]")]
struct ValidatePaddleSetupTransactionError {
    kind: ValidatePaddleSetupTransactionErrorKind,
    location: Location,
}

#[tracing::instrument(skip_all, err)]
fn validate_paddle_setup_transaction(
    txn: &serde_json::Value,
    expected_setup_price_id: &str,
    expected_customer_id: Option<&str>,
    expected_customer_email: Option<&str>,
    allow_checkout_binding: bool,
) -> Result<(String, Option<String>), ValidatePaddleSetupTransactionError> {
    use ValidatePaddleSetupTransactionErrorKind as Kind;
    let reject = |kind| ValidatePaddleSetupTransactionError {
        kind,
        location: std::panic::Location::caller(),
    };

    let status = txn["data"]["status"].as_str().unwrap_or("");
    if !is_completed_paddle_transaction_status(status) {
        return Err(reject(Kind::NotCompleted));
    }

    if txn["data"]["collection_mode"].as_str().unwrap_or("") != "automatic" {
        return Err(reject(Kind::NotAutomatic));
    }

    if !transaction_contains_price_id(txn, expected_setup_price_id) {
        return Err(reject(Kind::WrongPrice));
    }

    let customer_id = txn["data"]["customer_id"]
        .as_str()
        .ok_or_else(|| reject(Kind::NoCustomerId))?;

    if let Some(expected_customer_id) = expected_customer_id {
        if customer_id != expected_customer_id {
            return Err(reject(Kind::WrongAccount));
        }
    } else if let Some(expected_customer_email) = expected_customer_email {
        let txn_customer_email = txn["data"]["customer"]["email"]
            .as_str()
            .ok_or_else(|| reject(Kind::CustomerEmailUnavailable))?;
        if !txn_customer_email.eq_ignore_ascii_case(expected_customer_email) {
            return Err(reject(Kind::WrongAccount));
        }
    } else if !allow_checkout_binding {
        return Err(reject(Kind::NoBinding));
    }

    Ok((
        customer_id.to_string(),
        extract_paddle_payment_method_id(txn),
    ))
}

/// Failure modes for [`paddle_transaction_completed`]. Setup- and binding-level
/// rejections carry a fixed client message; transport and database failures map to
/// generic bodies.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum PaddleTransactionCompletedError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle API not configured [{location}]")]
    ApiNotConfigured { location: Location },

    #[error("Paddle setup price not configured [{location}]")]
    SetupPriceNotConfigured { location: Location },

    #[error("checkout binding unavailable [{location}]")]
    CheckoutBindingUnavailable { location: Location },

    #[error("checkout binding validation failed [{location}]")]
    BindingRejected {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("setup transaction validation failed [{location}]")]
    SetupRejected {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not verify the Paddle transaction [{location}]")]
    FetchTransaction {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for PaddleTransactionCompletedError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            PaddleTransactionCompletedError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            PaddleTransactionCompletedError::ApiNotConfigured { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured")
            }
            PaddleTransactionCompletedError::SetupPriceNotConfigured { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Paddle setup price not configured",
            ),
            PaddleTransactionCompletedError::CheckoutBindingUnavailable { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Checkout binding is unavailable. Contact support.",
            ),
            PaddleTransactionCompletedError::BindingRejected { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            PaddleTransactionCompletedError::SetupRejected { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            PaddleTransactionCompletedError::FetchTransaction { .. } => {
                (StatusCode::BAD_GATEWAY, "failed to verify transaction")
            }
            PaddleTransactionCompletedError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Frontend callback after Paddle checkout completion — records payment method reference locally
#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn paddle_transaction_completed(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PaddleTransactionCompletedRequest>,
) -> Result<Json<serde_json::Value>, PaddleTransactionCompletedError> {
    use PaddleTransactionCompletedErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
        tracing::warn!("Paddle API not configured");
        PaddleTransactionCompletedError::ApiNotConfigured {
            location: std::panic::Location::caller(),
        }
    })?;
    let setup_price_id = state.paddle_setup_price_id.as_ref().ok_or_else(|| {
        tracing::warn!("Paddle setup price not configured");
        PaddleTransactionCompletedError::SetupPriceNotConfigured {
            location: std::panic::Location::caller(),
        }
    })?;

    let existing_paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database())?
    .flatten();

    let user_email: Option<String> = if existing_paddle_customer_id.is_none() {
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_optional(&state.db)
            .await
            .with_context(Ctx::database())?
            .flatten()
    } else {
        None
    };

    let txn = fetch_paddle_transaction(&state.paddle_api_url, paddle_api_key, &req.transaction_id)
        .await
        .with_context(Ctx::fetch_transaction())?;
    let allow_checkout_binding =
        if existing_paddle_customer_id.is_none() && user_email.as_deref().is_none() {
            let secret = state.internal_service_secret.as_deref().ok_or_else(|| {
                tracing::warn!("checkout binding unavailable (no internal service secret)");
                PaddleTransactionCompletedError::CheckoutBindingUnavailable {
                    location: std::panic::Location::caller(),
                }
            })?;
            match validate_paddle_checkout_binding(&txn, secret, auth.user_id, org_id) {
                Ok(()) => true,
                Err(source) => {
                    return Err(PaddleTransactionCompletedError::BindingRejected {
                        source: Box::new(source),
                        location: std::panic::Location::caller(),
                    });
                }
            }
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
    .with_context(Ctx::setup_rejected())?;

    upsert_local_payment_method(
        &state.db,
        org_id,
        &req.transaction_id,
        paddle_payment_method_id.as_deref(),
        req.card_last4.as_deref(),
        req.card_brand.as_deref(),
    )
    .await
    .with_context(Ctx::database())?;

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
        tracing::error!(org_id = %org_id, error = ?e, "Failed to store paddle_customer_id");
    } else {
        tracing::info!("Stored paddle_customer_id for org {}", org_id);
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

/// Failure modes for [`fetch_paddle_transaction`]. All failures are surfaced to
/// the caller as a generic 502; none reach an HTTP client verbatim.
#[derive(Debug, thiserror::Error, CtxError)]
enum FetchPaddleTransactionError {
    #[error("could not reach the Paddle API [{location}]")]
    Transport {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle rate limited this server IP [{location}]")]
    RateLimited { location: Location },

    #[error("Paddle returned an error status [{location}]")]
    ApiStatus { location: Location },

    #[error("could not parse the Paddle response [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn fetch_paddle_transaction(
    api_url: &str,
    api_key: &str,
    transaction_id: &str,
) -> Result<serde_json::Value, FetchPaddleTransactionError> {
    use FetchPaddleTransactionError as E;
    use FetchPaddleTransactionErrorCtx as Ctx;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/transactions/{}", api_url, transaction_id))
        .query(&[("include", "customer")])
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .with_context(Ctx::transport())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS;
        let _body = resp.text().await.unwrap_or_default();
        return Err(if rate_limited {
            E::RateLimited {
                location: std::panic::Location::caller(),
            }
        } else {
            E::ApiStatus {
                location: std::panic::Location::caller(),
            }
        });
    }

    resp.json().await.with_context(Ctx::parse())
}

/// Failure modes for [`generate_paddle_customer_auth_token`]. Callers log the
/// failure and fall back; none reach an HTTP client verbatim.
#[derive(Debug, thiserror::Error, CtxError)]
enum GeneratePaddleCustomerAuthTokenError {
    #[error("could not reach the Paddle API [{location}]")]
    Transport {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle rate limited this server IP [{location}]")]
    RateLimited { location: Location },

    #[error("Paddle returned an error status [{location}]")]
    ApiStatus { location: Location },

    #[error("could not parse the Paddle response [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("response had no customer_auth_token [{location}]")]
    MissingToken { location: Location },
}

#[tracing::instrument(skip_all, err)]
async fn generate_paddle_customer_auth_token(
    api_url: &str,
    api_key: &str,
    customer_id: &str,
) -> Result<String, GeneratePaddleCustomerAuthTokenError> {
    use GeneratePaddleCustomerAuthTokenError as E;
    use GeneratePaddleCustomerAuthTokenErrorCtx as Ctx;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/customers/{}/auth-token", api_url, customer_id))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .with_context(Ctx::transport())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS;
        let _body = resp.text().await.unwrap_or_default();
        return Err(if rate_limited {
            E::RateLimited {
                location: std::panic::Location::caller(),
            }
        } else {
            E::ApiStatus {
                location: std::panic::Location::caller(),
            }
        });
    }

    let body: serde_json::Value = resp.json().await.with_context(Ctx::parse())?;
    body["data"]["customer_auth_token"]
        .as_str()
        .map(|token| token.to_string())
        .ok_or_else(|| E::MissingToken {
            location: std::panic::Location::caller(),
        })
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

/// Categories of credit-purchase transaction validation failure (internal only;
/// the handler renders a fixed body).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ValidateCreditPurchaseTransactionErrorKind {
    PriceMismatch,
    MissingMetadata,
    NotCreditPurchase,
    WrongAccount,
    WrongUser,
    AmountMismatch,
    CreditMismatch,
}

/// Failure modes for [`validate_credit_purchase_transaction`] (source-less domain
/// failures; callers box this error as a `#[source]`).
#[derive(Debug, thiserror::Error)]
#[error("invalid credit purchase transaction ({kind:?}) [{location}]")]
struct ValidateCreditPurchaseTransactionError {
    kind: ValidateCreditPurchaseTransactionErrorKind,
    location: Location,
}

#[tracing::instrument(skip_all, err)]
fn validate_credit_purchase_transaction(
    txn: &serde_json::Value,
    org_id: Uuid,
    user_id: Uuid,
    purchase: &ResolvedCreditPurchase,
) -> Result<(), ValidateCreditPurchaseTransactionError> {
    use ValidateCreditPurchaseTransactionErrorKind as Kind;
    let invalid = |kind| ValidateCreditPurchaseTransactionError {
        kind,
        location: std::panic::Location::caller(),
    };

    if let Some(expected_price_id) = purchase.price_id.as_deref()
        && !transaction_contains_price_id(txn, expected_price_id)
    {
        return Err(invalid(Kind::PriceMismatch));
    }

    let custom_data = txn["data"]["custom_data"]
        .as_object()
        .ok_or_else(|| invalid(Kind::MissingMetadata))?;
    if custom_data
        .get("caution_credit_purchase")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return Err(invalid(Kind::NotCreditPurchase));
    }

    let org_id_string = org_id.to_string();
    if custom_data
        .get("caution_credit_purchase_org_id")
        .and_then(|value| value.as_str())
        != Some(org_id_string.as_str())
    {
        return Err(invalid(Kind::WrongAccount));
    }

    let user_id_string = user_id.to_string();
    if custom_data
        .get("caution_credit_purchase_user_id")
        .and_then(|value| value.as_str())
        != Some(user_id_string.as_str())
    {
        return Err(invalid(Kind::WrongUser));
    }

    if custom_data
        .get("caution_credit_purchase_purchase_cents")
        .and_then(|value| value.as_i64())
        != Some(purchase.purchase_cents)
    {
        return Err(invalid(Kind::AmountMismatch));
    }

    if custom_data
        .get("caution_credit_purchase_credit_cents")
        .and_then(|value| value.as_i64())
        != Some(purchase.credit_cents)
    {
        return Err(invalid(Kind::CreditMismatch));
    }

    Ok(())
}

fn build_credit_purchase_transaction_item(purchase: &ResolvedCreditPurchase) -> serde_json::Value {
    if let Some(price_id) = purchase.price_id.as_ref() {
        return serde_json::json!({
            "price_id": price_id,
            "quantity": 1,
        });
    }

    serde_json::json!({
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
    })
}

/// Failure modes for [`get_credit_balance`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCreditBalanceError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetCreditBalanceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetCreditBalanceError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetCreditBalanceError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_credit_balance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetCreditBalanceError> {
    use GetCreditBalanceErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let balance_cents = get_ledger_balance_cents(&state.db, org_id)
        .await
        .with_context(Ctx::database())?;

    Ok(Json(serde_json::json!({
        "balance_cents": balance_cents,
        "balance_display": format!("${:.2}", balance_cents as f64 / 100.0),
    })))
}

/// Lists the configured credit packages. This handler is infallible.
#[tracing::instrument(skip_all)]
pub async fn get_credit_packages(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Json<serde_json::Value> {
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

    Json(serde_json::json!({ "packages": packages }))
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

/// Categories of credit-purchase request resolution failure (internal only; the
/// handler renders a fixed body).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ResolveCreditPurchaseRequestErrorKind {
    BothProvided,
    NeitherProvided,
    InvalidIndex,
    BelowMinimum,
}

/// Failure modes for [`resolve_credit_purchase_request`] (source-less domain
/// failures; the caller surfaces `client_message` to the client).
#[derive(Debug, thiserror::Error)]
#[error("invalid credit purchase request ({kind:?}) [{location}]")]
struct ResolveCreditPurchaseRequestError {
    kind: ResolveCreditPurchaseRequestErrorKind,
    location: Location,
}

#[tracing::instrument(skip_all, err)]
fn resolve_credit_purchase_request(
    req: &PurchaseCreditsRequest,
    credit_packages: &[CreditPackage],
    paddle_price_ids: &[Option<String>; 3],
) -> Result<ResolvedCreditPurchase, ResolveCreditPurchaseRequestError> {
    use ResolveCreditPurchaseRequestErrorKind as Kind;
    let reject = |kind| ResolveCreditPurchaseRequestError {
        kind,
        location: std::panic::Location::caller(),
    };

    match (req.package_index, req.amount_cents) {
        (Some(_), Some(_)) => Err(reject(Kind::BothProvided)),
        (None, None) => Err(reject(Kind::NeitherProvided)),
        (Some(package_index), None) => {
            let pkg = credit_packages
                .get(package_index)
                .ok_or_else(|| reject(Kind::InvalidIndex))?;

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
                return Err(reject(Kind::BelowMinimum));
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

/// Failure modes for [`purchase_credits`]. Request/validation rejections carry a
/// fixed client message; transport and database failures map to generic bodies.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum PurchaseCreditsError {
    #[error("credit purchase request could not be resolved [{location}]")]
    RequestInvalid {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("credit purchase transaction rejected [{location}]")]
    TransactionRejected {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("request rejected [{location}]")]
    BadRequest { location: Location },

    #[error("Paddle not configured ({message}) [{location}]")]
    NotConfigured {
        message: &'static str,
        location: Location,
    },

    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not reach the Paddle API [{location}]")]
    PaddleTransport {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Paddle returned an error status [{location}]")]
    PaddleStatus { location: Location },

    #[error("missing transaction ID in Paddle response [{location}]")]
    TxnIdMissing { location: Location },

    #[error("failed to record credit purchase [{location}]")]
    IntentInsert { location: Location },

    #[error("transaction payment failed [{location}]")]
    PaymentRequired { location: Location },
}

impl IntoResponse for PurchaseCreditsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            PurchaseCreditsError::RequestInvalid { .. } => (StatusCode::BAD_REQUEST, "bad request"),
            PurchaseCreditsError::TransactionRejected { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            PurchaseCreditsError::BadRequest { .. } => (StatusCode::BAD_REQUEST, "bad request"),
            PurchaseCreditsError::NotConfigured { message, .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, *message)
            }
            PurchaseCreditsError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            PurchaseCreditsError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            PurchaseCreditsError::PaddleTransport { .. } => {
                (StatusCode::BAD_GATEWAY, "payment provider error")
            }
            PurchaseCreditsError::PaddleStatus { .. } => {
                (StatusCode::BAD_GATEWAY, "payment provider error")
            }
            PurchaseCreditsError::TxnIdMissing { .. } => (
                StatusCode::BAD_GATEWAY,
                "Missing transaction ID in Paddle response",
            ),
            PurchaseCreditsError::IntentInsert { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to record credit purchase",
            ),
            PurchaseCreditsError::PaymentRequired { .. } => {
                (StatusCode::PAYMENT_REQUIRED, "transaction payment failed")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn purchase_credits(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PurchaseCreditsRequest>,
) -> Result<Json<serde_json::Value>, PurchaseCreditsError> {
    use PurchaseCreditsErrorCtx as Ctx;

    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let purchase = match resolve_credit_purchase_request(
        &req,
        &credit_packages,
        &state.paddle_credits_price_ids,
    ) {
        Ok(purchase) => purchase,
        Err(source) => {
            tracing::warn!(user_id = %auth.user_id, error = %source, "invalid credit purchase request");
            return Err(PurchaseCreditsError::RequestInvalid {
                source: Box::new(source),
                location: std::panic::Location::caller(),
            });
        }
    };

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    if req.transaction_id.is_none() {
        let paddle_api_key = state.paddle_api_key.as_ref().ok_or_else(|| {
            tracing::warn!("Paddle API not configured");
            PurchaseCreditsError::NotConfigured {
                message: "Paddle API not configured",
                location: std::panic::Location::caller(),
            }
        })?;
        let paddle_client_token = state.paddle_client_token.as_ref().ok_or_else(|| {
            tracing::warn!("Paddle checkout not configured");
            PurchaseCreditsError::NotConfigured {
                message: "Paddle checkout not configured",
                location: std::panic::Location::caller(),
            }
        })?;

        let paddle_customer_id: Option<String> = sqlx::query_scalar(
            "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
        .flatten();

        let customer_auth_token = if let Some(customer_id) = paddle_customer_id.as_deref() {
            Some(
                generate_paddle_customer_auth_token(
                    &state.paddle_api_url,
                    paddle_api_key,
                    customer_id,
                )
                .await
                .with_context(Ctx::paddle_transport())?,
            )
        } else {
            None
        };

        let custom_data = build_credit_purchase_custom_data(org_id, auth.user_id, &purchase);
        let item = build_credit_purchase_transaction_item(&purchase);
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
            .with_context(Ctx::paddle_transport())?;

        if !response.status().is_success() {
            let status = response.status();
            let err_body = response.text().await.unwrap_or_default();
            tracing::error!(org_id = %org_id, status = %status, body = %err_body, "Paddle transaction failed");
            return Err(PurchaseCreditsError::PaddleStatus {
                location: std::panic::Location::caller(),
            });
        }

        let resp: serde_json::Value = response
            .json()
            .await
            .with_context(Ctx::paddle_transport())?;

        let Some(transaction_id) = resp["data"]["id"].as_str().map(|s| s.to_string()) else {
            tracing::error!(org_id = %org_id, "missing transaction ID in Paddle response");
            return Err(PurchaseCreditsError::TxnIdMissing {
                location: std::panic::Location::caller(),
            });
        };

        // Record the server-authoritative credit amount before handing the
        // transaction id back to the frontend. Both the completion callback and
        // the Paddle webhook credit from this row, never from client-supplied
        // custom_data.
        if let Err(e) = sqlx::query(
            "INSERT INTO credit_purchase_intents
                 (paddle_transaction_id, organization_id, user_id, purchase_cents, credit_cents, paddle_price_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (paddle_transaction_id) DO NOTHING",
        )
        .bind(&transaction_id)
        .bind(org_id)
        .bind(auth.user_id)
        .bind(purchase.purchase_cents)
        .bind(purchase.credit_cents)
        .bind(purchase.price_id.as_deref())
        .execute(&state.db)
        .await
        {
            tracing::error!(transaction_id = %transaction_id, error = ?e, "failed to record credit purchase intent");
            return Err(PurchaseCreditsError::IntentInsert {
                location: std::panic::Location::caller(),
            });
        }

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
            tracing::warn!("Paddle API not configured");
            PurchaseCreditsError::NotConfigured {
                message: "Paddle API not configured",
                location: std::panic::Location::caller(),
            }
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
            .with_context(Ctx::paddle_transport())?;

        if !verify_resp.status().is_success() {
            tracing::warn!(transaction_id = %transaction_id, status = %verify_resp.status(), "Paddle transaction verification failed");
            return Err(PurchaseCreditsError::BadRequest {
                location: std::panic::Location::caller(),
            });
        }

        let verify_data: serde_json::Value = verify_resp
            .json()
            .await
            .with_context(Ctx::paddle_transport())?;

        if let Err(source) =
            validate_credit_purchase_transaction(&verify_data, org_id, auth.user_id, &purchase)
        {
            tracing::warn!(transaction_id = %transaction_id, error = %source, "credit purchase validation failed");
            return Err(PurchaseCreditsError::TransactionRejected {
                source: Box::new(source),
                location: std::panic::Location::caller(),
            });
        }

        let txn_customer_id = verify_data["data"]["customer_id"].as_str().unwrap_or("");
        let org_paddle_customer_id: Option<String> = sqlx::query_scalar(
            "SELECT paddle_customer_id FROM billing_config WHERE organization_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
        .flatten();

        if let Some(ref expected_cid) = org_paddle_customer_id {
            if txn_customer_id != expected_cid.as_str() {
                tracing::warn!(transaction_id = %transaction_id, "Paddle transaction customer_id does not match user's customer_id");
                return Err(PurchaseCreditsError::BadRequest {
                    location: std::panic::Location::caller(),
                });
            }
        } else {
            if txn_customer_id.is_empty() {
                tracing::warn!(org_id = %org_id, transaction_id = %transaction_id, "no billing account on file");
                return Err(PurchaseCreditsError::BadRequest {
                    location: std::panic::Location::caller(),
                });
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
                tracing::error!(org_id = %org_id, error = ?e, "failed to store paddle_customer_id");
            } else {
                tracing::info!("Stored paddle_customer_id for org {}", org_id);
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
    .with_context(Ctx::database())?;

    let already_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credit_ledger WHERE paddle_transaction_id = $1)",
    )
    .bind(&transaction_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::database())?;

    if already_exists {
        let balance_cents = get_ledger_balance_cents(&state.db, org_id)
            .await
            .with_context(Ctx::database())?;

        return Ok(Json(serde_json::json!({
            "success": true,
            "balance_cents": balance_cents,
            "balance_display": format!("${:.2}", balance_cents as f64 / 100.0),
            "already_processed": true,
        })));
    }

    if is_failed_credit_purchase_status(&transaction_status) {
        return Err(PurchaseCreditsError::PaymentRequired {
            location: std::panic::Location::caller(),
        });
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

    // Credit the server-authoritative amount recorded when this transaction was
    // created, never the amount derived from the (client-influenced) request or
    // transaction custom_data. A missing intent row means this is not a
    // server-created credit purchase and must not be credited.
    let intent_credit_cents: Option<i64> = sqlx::query_scalar(
        "SELECT credit_cents FROM credit_purchase_intents WHERE paddle_transaction_id = $1",
    )
    .bind(&transaction_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::database())?;

    let Some(authoritative_credit_cents) = intent_credit_cents else {
        tracing::error!(transaction_id = %transaction_id, org_id = %org_id, "No credit purchase intent for transaction; refusing to credit");
        return Err(PurchaseCreditsError::BadRequest {
            location: std::panic::Location::caller(),
        });
    };

    let new_balance = apply_credit(
        &state.db,
        org_id,
        authoritative_credit_cents,
        "purchase",
        &purchase.description,
        Some(&transaction_id),
        None,
    )
    .await
    .with_context(Ctx::database())?;

    tracing::info!(
        "Credit purchase: org={}, user={}, txn={}, +{} cents, new_balance={}",
        org_id,
        auth.user_id,
        transaction_id,
        purchase.credit_cents,
        new_balance
    );

    if new_balance > 0
        && let Ok(org_id) = get_user_primary_org(&state.db, auth.user_id).await
    {
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
                    "Failed to clear credit suspension for org {}: {:?}",
                    org_id,
                    e
                );
            }

            let _ = call_internal_unsuspend(&state, org_id).await;
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "balance_cents": new_balance,
        "balance_display": format!("${:.2}", new_balance as f64 / 100.0),
    })))
}

/// Failure modes for [`get_credit_ledger`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCreditLedgerError {
    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database query failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetCreditLedgerError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetCreditLedgerError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetCreditLedgerError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_credit_ledger(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, GetCreditLedgerError> {
    use GetCreditLedgerErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let rows: Vec<CreditLedgerRow> = sqlx::query_as(
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


    .with_context(Ctx::database())?;

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

/// Failure modes for [`redeem_credit_code`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum RedeemCreditCodeError {
    #[error("request rejected ({message}) [{location}]")]
    BadRequest {
        message: &'static str,
        location: Location,
    },

    #[error("invalid or already redeemed code [{location}]")]
    InvalidCode { location: Location },

    #[error("could not look up the primary organization [{location}]")]
    OrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database operation failed [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for RedeemCreditCodeError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            RedeemCreditCodeError::BadRequest { message, .. } => {
                (StatusCode::BAD_REQUEST, *message)
            }
            RedeemCreditCodeError::InvalidCode { .. } => {
                (StatusCode::NOT_FOUND, "Invalid or already redeemed code")
            }
            RedeemCreditCodeError::OrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            RedeemCreditCodeError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn redeem_credit_code(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, RedeemCreditCodeError> {
    use RedeemCreditCodeError as E;
    use RedeemCreditCodeErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::org_lookup())?;

    let code = match body.get("code").and_then(|v| v.as_str()) {
        Some(code) => code.trim().replace('-', ""),
        None => {
            return Err(E::BadRequest {
                message: "Missing 'code' field",
                location: std::panic::Location::caller(),
            });
        }
    };

    if code.is_empty() {
        return Err(E::BadRequest {
            message: "Code cannot be empty",
            location: std::panic::Location::caller(),
        });
    }

    let mut tx = state.db.begin().await.with_context(Ctx::database())?;

    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, amount_cents FROM credit_codes WHERE UPPER(code) = UPPER($1) AND redeemed_by IS NULL FOR UPDATE"
    )
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await


    .with_context(Ctx::database())?;

    let (code_id, amount_cents) = match row {
        Some(r) => r,
        None => {
            return Err(E::InvalidCode {
                location: std::panic::Location::caller(),
            });
        }
    };

    sqlx::query("UPDATE credit_codes SET redeemed_by = $1, redeemed_at = NOW() WHERE id = $2")
        .bind(auth.user_id)
        .bind(code_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::database())?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
         VALUES ($1, $2, 'code_redemption', 'Redeemed credit code')",
    )
    .bind(org_id)
    .bind(amount_cents)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::database())?;

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id)
        .await
        .with_context(Ctx::database())?;

    tx.commit().await.with_context(Ctx::database())?;

    tracing::info!(
        "Credit code redeemed: user={}, code_id={}, +{} cents, new_balance={}",
        auth.user_id,
        code_id,
        amount_cents,
        new_balance
    );

    if new_balance > 0 {
        let suspended: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                .bind(org_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .flatten();

        if suspended.is_some() {
            tracing::info!(
                "Clearing credit suspension for org {} after credit code redemption",
                org_id
            );
            if let Err(e) =
                sqlx::query("UPDATE organizations SET credit_suspended_at = NULL WHERE id = $1")
                    .bind(org_id)
                    .execute(&state.db)
                    .await
            {
                tracing::error!(
                    "Failed to clear credit suspension for org {} after credit code redemption: {}",
                    org_id,
                    e
                );
            }

            let _ = call_internal_unsuspend(&state, org_id).await;
        }
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "amount_cents": amount_cents,
        "new_balance": new_balance,
    })))
}

/// Failure modes for [`apply_credit`]. All failures carry a source.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ApplyCreditError {
    #[error("could not begin transaction [{location}]")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not insert credit ledger entry [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not compute balance [{location}]")]
    Balance {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not commit transaction [{location}]")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Atomically insert a credit_ledger row and return the derived balance.
#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn apply_credit(
    db: &PgPool,
    org_id: Uuid,
    delta_cents: i64,
    entry_type: &str,
    description: &str,
    paddle_txn_id: Option<&str>,
    invoice_id: Option<Uuid>,
) -> Result<i64, ApplyCreditError> {
    use ApplyCreditErrorCtx as Ctx;

    let mut tx = db.begin().await.with_context(Ctx::begin())?;

    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description, paddle_transaction_id, invoice_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (paddle_transaction_id) DO NOTHING"
    )
    .bind(org_id)
    .bind(delta_cents)
    .bind(entry_type)
    .bind(description)
    .bind(paddle_txn_id)
    .bind(invoice_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::insert())?;

    let new_balance = get_ledger_balance_cents(&mut *tx, org_id)
        .await
        .with_context(Ctx::balance())?;

    tx.commit().await.with_context(Ctx::commit())?;

    Ok(new_balance)
}
#[cfg(test)]
mod tests {
    use super::{
        CreditPackage, PurchaseCreditsRequest, build_paddle_checkout_custom_data,
        extract_paddle_payment_method_id, resolve_credit_purchase_request,
        transaction_contains_price_id, validate_credit_purchase_transaction,
        validate_paddle_checkout_binding, validate_paddle_setup_transaction,
    };
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

        assert!(format!("{err:?}").contains("NeitherProvided"));
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

        assert!(format!("{err:?}").contains("InvalidIndex"));
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

        assert!(format!("{err:?}").contains("BelowMinimum"));
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

        assert!(format!("{err:?}").contains("BothProvided"));
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
        assert!(format!("{err:?}").contains("WrongUser"));
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

        assert!(format!("{err:?}").contains("WrongAccount"));
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

        assert!(format!("{err:?}").contains("WrongPrice"));
    }
}

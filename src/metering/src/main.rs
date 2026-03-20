// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod calculator;
mod cost_explorer;
mod credits;
mod paddle;
mod providers;
mod types;
mod webhooks;

use types::*;

pub struct AppState {
    pub pool: sqlx::PgPool,
    pub paddle: paddle::PaddleClient,
    pub calculator: calculator::CostCalculator,
    pub internal_service_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must be set")?;

    let paddle_api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
    let paddle_api_key = std::env::var("PADDLE_API_KEY").unwrap_or_default();
    let paddle_webhook_secret = std::env::var("PADDLE_WEBHOOK_SECRET").unwrap_or_default();

    if !paddle_api_key.is_empty() && paddle_api_url.is_empty() {
        anyhow::bail!("PADDLE_API_KEY is set but PADDLE_API_URL is not — set PADDLE_API_URL to the Paddle API base URL (e.g. https://sandbox-api.paddle.com or https://api.paddle.com)");
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    tracing::info!("Connected to database");

    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok().filter(|s| !s.is_empty());
    if internal_service_secret.is_none() {
        tracing::warn!("INTERNAL_SERVICE_SECRET not set — metering API routes are unauthenticated");
    }

    let paddle = paddle::PaddleClient::new(paddle_api_url, paddle_api_key, paddle_webhook_secret);
    let calculator = calculator::CostCalculator::new(calculator::PricingRules::default());

    let state = Arc::new(AppState {
        pool,
        paddle,
        calculator,
        internal_service_secret,
    });

    // Start background metering collection task
    let collection_state = state.clone();
    let collection_interval_secs: u64 = std::env::var("METERING_INTERVAL_SECS")
        .unwrap_or_else(|_| "300".to_string()) // 5 minutes default
        .parse()
        .unwrap_or(300);

    tokio::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(
                run_collection_loop(collection_state.clone(), collection_interval_secs)
            );
            if let Err(e) = futures::FutureExt::catch_unwind(result).await {
                tracing::error!("Collection loop panicked: {:?}. Restarting in 60s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    // Start monthly billing cycle (checks daily, runs at month-end)
    let billing_state = state.clone();
    tokio::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(
                run_monthly_billing_loop(billing_state.clone())
            );
            if let Err(e) = futures::FutureExt::catch_unwind(result).await {
                tracing::error!("Monthly billing loop panicked: {:?}. Restarting in 60s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    // Start dunning enforcement loop (checks every hour)
    let dunning_state = state.clone();
    tokio::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(
                run_dunning_loop(dunning_state.clone())
            );
            if let Err(e) = futures::FutureExt::catch_unwind(result).await {
                tracing::error!("Dunning loop panicked: {:?}. Restarting in 60s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    let enable_test_endpoints = std::env::var("ENABLE_TEST_ENDPOINTS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Authenticated API routes — require INTERNAL_SERVICE_SECRET
    let mut api_routes = Router::new()
        .route("/api/resources/track", post(track_resource))
        .route("/api/resources/{resource_id}/untrack", post(untrack_resource))
        .route("/api/resources", get(list_tracked_resources))
        .route("/api/usage/{user_id}", get(get_user_usage))
        .route("/api/collect", post(trigger_collection))
        // AWS Cost Explorer endpoints
        .route("/api/aws/costs/sync", post(sync_aws_costs))
        .route("/api/aws/costs/{org_id}", get(get_aws_org_costs))
        .route("/api/aws/costs", get(get_all_aws_costs))
        // Monthly billing
        .route("/api/billing/monthly", post(trigger_monthly_billing))
        // User-facing billing dashboard
        .route("/api/billing/estimate/{org_id}", get(get_billing_estimate));

    // Test endpoints: only available when ENABLE_TEST_ENDPOINTS=true
    if enable_test_endpoints {
        tracing::warn!("Test endpoints enabled — do NOT use in production");
        api_routes = api_routes
            .route("/test/simulate-usage", post(test_simulate_usage))
            .route("/test/simulate-paddle-transaction", post(test_simulate_paddle_transaction));
    }

    let api_routes = api_routes
        .layer(middleware::from_fn_with_state(state.clone(), internal_auth_middleware));

    // Webhook rate limiter: 30 requests per minute per IP
    let webhook_limiter = RateLimiter::new(30, std::time::Duration::from_secs(60));

    // Public routes — no auth required (health check, webhooks have their own signature verification)
    let webhook_routes = Router::new()
        .route("/webhooks/paddle", post(webhooks::paddle_webhook_handler))
        .layer(middleware::from_fn_with_state(webhook_limiter, webhook_rate_limit_middleware));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .merge(webhook_routes);

    let app = Router::new()
        .merge(api_routes)
        .merge(public_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:8083";
    tracing::info!("Metering service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

/// Simple per-IP rate limiter for webhook endpoints.
/// Allows `max_requests` per `window` duration per source IP.
#[derive(Clone)]
struct RateLimiter {
    requests: Arc<tokio::sync::Mutex<HashMap<String, Vec<std::time::Instant>>>>,
    max_requests: usize,
    window: std::time::Duration,
    max_entries: usize,
}

impl RateLimiter {
    fn new(max_requests: usize, window: std::time::Duration) -> Self {
        Self {
            requests: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max_requests,
            window,
            max_entries: 10_000,
        }
    }

    async fn check(&self, ip: &str) -> bool {
        let now = std::time::Instant::now();
        let mut map = self.requests.lock().await;

        // Evict stale entries to prevent unbounded growth
        if map.len() > self.max_entries {
            map.retain(|_, entries| {
                entries.last().map_or(false, |t| now.duration_since(*t) < self.window)
            });
        }

        let entries = map.entry(ip.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() >= self.max_requests {
            return false;
        }
        entries.push(now);
        true
    }
}

/// Rate-limiting middleware for webhook routes.
async fn webhook_rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = req.headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').last())
        .unwrap_or("unknown")
        .trim()
        .to_string();

    if !limiter.check(&ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    next.run(req).await
}

/// Internal service auth middleware — checks x-internal-service-secret header.
/// If INTERNAL_SERVICE_SECRET is not configured, allows all requests (dev mode).
async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(ref configured_secret) = state.internal_service_secret else {
        // No secret configured — allow (dev mode, already warned at startup)
        return next.run(request).await;
    };

    let provided = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());

    match provided {
        Some(s) if s == configured_secret.as_str() => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "Invalid or missing internal service secret").into_response(),
    }
}

#[derive(serde::Deserialize)]
struct TrackResourceRequest {
    resource_id: String,
    user_id: uuid::Uuid,
    provider: Provider,
    instance_type: Option<String>,
    region: Option<String>,
    metadata: Option<serde_json::Value>,
}

async fn track_resource(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrackResourceRequest>,
) -> impl IntoResponse {
    let metadata = req.metadata.unwrap_or(serde_json::json!({}));

    let result = sqlx::query(
        r#"
        INSERT INTO tracked_resources (resource_id, user_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'running', NOW(), NOW())
        ON CONFLICT (resource_id) DO UPDATE SET
            status = 'running',
            started_at = COALESCE(tracked_resources.started_at, NOW()),
            last_billed_at = COALESCE(tracked_resources.last_billed_at, NOW())
        "#,
    )
    .bind(&req.resource_id)
    .bind(req.user_id)
    .bind(req.provider.as_str())
    .bind(&req.instance_type)
    .bind(&req.region)
    .bind(&metadata)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!("Now tracking resource: {}", req.resource_id);
            (StatusCode::OK, Json(serde_json::json!({"status": "tracking"})))
        }
        Err(e) => {
            tracing::error!("Failed to track resource: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

async fn untrack_resource(
    State(state): State<Arc<AppState>>,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    // First collect any remaining usage before stopping tracking
    if let Err(e) = collect_resource_usage(&state, &resource_id).await {
        tracing::warn!("Failed to collect final usage for {}: {}", resource_id, e);
    }

    let result = sqlx::query(
        r#"
        UPDATE tracked_resources
        SET status = 'stopped', stopped_at = NOW()
        WHERE resource_id = $1
        "#,
    )
    .bind(&resource_id)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!("Stopped tracking resource: {}", resource_id);
            (StatusCode::OK, Json(serde_json::json!({"status": "stopped"})))
        }
        Err(e) => {
            tracing::error!("Failed to untrack resource: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

async fn list_tracked_resources(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let result = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        ORDER BY started_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await;

    match result {
        Ok(resources) => (StatusCode::OK, Json(serde_json::json!({"resources": resources}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn get_user_usage(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        r#"
        SELECT
            provider,
            resource_type,
            SUM(quantity)::float8 as total_quantity,
            SUM(cost_usd)::float8 as total_cost
        FROM usage_records
        WHERE user_id = $1
        AND recorded_at >= NOW() - INTERVAL '30 days'
        GROUP BY provider, resource_type
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await;

    match result {
        Ok(rows) => {
            let usage: Vec<serde_json::Value> = rows.iter().map(|row| {
                serde_json::json!({
                    "provider": row.get::<String, _>("provider"),
                    "resource_type": row.get::<String, _>("resource_type"),
                    "total_quantity": row.get::<Option<f64>, _>("total_quantity"),
                    "total_cost": row.get::<Option<f64>, _>("total_cost"),
                })
            }).collect();
            (StatusCode::OK, Json(serde_json::json!({"usage": usage})))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn trigger_collection(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Bypass advisory lock for explicitly triggered collections — the lock only
    // prevents duplicate background loop runs, not manual API invocations.
    match run_collection_cycle_inner(&state).await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({"collected": count}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn run_collection_loop(state: Arc<AppState>, interval_secs: u64) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        if let Err(e) = run_collection_cycle(&state).await {
            tracing::error!("Metering collection failed: {}", e);
        }
    }
}

/// Monthly billing loop - runs daily, triggers billing on the last day of each month
async fn run_monthly_billing_loop(state: Arc<AppState>) {
    // Check once per hour
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;

        // Process subscription renewals on every tick
        if let Err(e) = run_subscription_billing(&state).await {
            tracing::error!("Subscription billing failed: {}", e);
        }

        let now = time::OffsetDateTime::now_utc();
        let today = now.date();
        let current_month = today.month();

        // Check if it's the last day of the month (or first few days of next month as fallback)
        let is_last_day = is_last_day_of_month(today);
        let is_first_of_month = today.day() <= 3; // Fallback: run in first 3 days if we missed month-end

        // Check database for whether we've already billed this month (survives restarts)
        let year_month = format!("{}-{:02}", now.year(), current_month as u8);
        let already_billed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM usage_records WHERE resource_id LIKE 'monthly-%' AND recorded_at >= $1::timestamptz)"
        )
        .bind(format!("{}-01T00:00:00Z", year_month))
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if (is_last_day || (is_first_of_month && !already_billed)) && !already_billed {
            tracing::info!("Running monthly billing cycle for {}", current_month);

            if let Err(e) = run_monthly_billing_cycle(&state).await {
                tracing::error!("Monthly billing cycle failed: {}", e);
            } else {
                tracing::info!("Monthly billing cycle completed for {}", current_month);
            }
        }
    }
}

/// Check if today is the last day of the month
fn is_last_day_of_month(date: time::Date) -> bool {
    let next_day = date + time::Duration::days(1);
    next_day.month() != date.month()
}

/// Run the monthly billing cycle
async fn run_monthly_billing_cycle(state: &AppState) -> Result<()> {
    if !try_advisory_lock(&state.pool, LOCK_MONTHLY_BILLING).await {
        tracing::debug!("Monthly billing skipped — another instance holds the lock");
        return Ok(());
    }
    let result = run_monthly_billing_cycle_inner(state).await;
    advisory_unlock(&state.pool, LOCK_MONTHLY_BILLING).await;
    result
}

async fn run_monthly_billing_cycle_inner(state: &AppState) -> Result<()> {
    // Get previous month's date range (bill for the month that just ended)
    let (start_date, end_date) = cost_explorer::previous_month_billing_period();

    tracing::info!(
        "Fetching AWS costs for billing period {} to {}",
        start_date,
        end_date
    );

    // Create Cost Explorer client
    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .context("Failed to create Cost Explorer client")?;

    // Get costs for all orgs
    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .context("Failed to fetch AWS costs")?;

    tracing::info!("Found costs for {} organizations", org_costs.len());

    let now = time::OffsetDateTime::now_utc();

    for (org_id, cost_data) in &org_costs {
        // Parse org_id as UUID
        let user_id: uuid::Uuid = match org_id.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!("Skipping non-UUID org_id: {}", org_id);
                continue;
            }
        };

        if cost_data.total_cost < 0.01 {
            tracing::debug!("Skipping org {} with negligible cost: ${:.4}", org_id, cost_data.total_cost);
            continue;
        }

        tracing::info!(
            "Billing org {} for ${:.2} (period: {} to {})",
            org_id,
            cost_data.total_cost,
            start_date,
            end_date
        );

        // Record the monthly usage
        let result = sqlx::query(
            r#"
            INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
            VALUES ($1, $2, 'aws', 'monthly_total', $3, 'usd', $3, $4, $5)
            "#,
        )
        .bind(user_id)
        .bind(format!("monthly-{}", start_date))
        .bind(cost_data.total_cost)
        .bind(now)
        .bind(serde_json::json!({
            "source": "aws_cost_explorer",
            "billing_period": {
                "start": start_date,
                "end": end_date,
            },
            "services": cost_data.costs_by_service,
        }))
        .execute(&state.pool)
        .await;

        if let Err(e) = result {
            tracing::error!("Failed to record monthly usage for {}: {}", org_id, e);
            continue;
        }

        let total_cost_cents = (cost_data.total_cost * 100.0).round() as i64;
        let billing_period = format!("{} to {}", start_date, end_date);

        // Skip credit deduction for users with tracked resources — they are billed in real-time
        let has_tracked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tracked_resources WHERE user_id = $1)"
        )
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if has_tracked {
            tracing::info!(
                "Skipping monthly credit deduction for org {} — billed in real-time via tracked resources",
                org_id
            );
            continue;
        }

        // Check and deduct prepaid credits before creating Paddle transaction
        let (credits_applied, remainder_cents) = credits::apply_credit_deduction(
            &state.pool,
            user_id,
            total_cost_cents,
            &format!("Monthly billing: {}", billing_period),
            None,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Credit deduction failed for {}: {}, falling back to full charge", org_id, e);
            (0, total_cost_cents)
        });

        if credits_applied > 0 {
            tracing::info!(
                "Applied {} cents in credits for org {} (remainder: {} cents)",
                credits_applied, org_id, remainder_cents
            );
        }

        if remainder_cents == 0 {
            // Fully covered by credits — record a credits-covered invoice, skip Paddle
            let invoice_number = format!("INV-CR-{}-{}", &org_id[..8], start_date);
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO invoices (
                    user_id, invoice_number,
                    amount_cents, currency, status, payment_status,
                    billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                "#,
            )
            .bind(user_id)
            .bind(&invoice_number)
            .bind(total_cost_cents)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to insert credits-covered invoice for org {}: {}", org_id, e);
            }

            tracing::info!(
                "Org {} billing fully covered by credits (${:.2})",
                org_id, total_cost_cents as f64 / 100.0
            );
            continue;
        }

        // Create Paddle transaction for the remainder
        let remainder_cost = remainder_cents as f64 / 100.0;
        let line_items = paddle::PaddleClient::line_items_from_cost_data(
            org_id,
            remainder_cost,
            &billing_period,
            &serde_json::json!(cost_data.costs_by_service),
        );

        if line_items.is_empty() {
            tracing::debug!("No billable items for org {}, skipping Paddle transaction", org_id);
            continue;
        }

        // Resolve the actual user_id from the org for billing_config lookup
        let billing_user_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1"
        )
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;

        let Some(billing_user_id) = billing_user_id else {
            tracing::warn!("No user found for org {}, skipping Paddle charge", org_id);
            continue;
        };

        // Look up the user's Paddle customer ID
        let paddle_customer = sqlx::query(
            "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1",
        )
        .bind(billing_user_id)
        .fetch_optional(&state.pool)
        .await?;

        let paddle_customer_id: Option<String> = paddle_customer
            .and_then(|row| row.get::<Option<String>, _>("paddle_customer_id"));

        if let Some(customer_id) = paddle_customer_id {
            match state.paddle.create_transaction(&customer_id, line_items).await {
                Ok(txn) => {
                    tracing::info!(
                        "Created Paddle transaction {} for org {} (${:.2}, after ${:.2} credits)",
                        txn.id, org_id, remainder_cost, credits_applied as f64 / 100.0
                    );
                    // Record the invoice locally with paddle_transaction_id
                    if let Err(e) = sqlx::query(
                        r#"
                        INSERT INTO invoices (
                            paddle_transaction_id, user_id, invoice_number,
                            amount_cents, currency, status, payment_status,
                            billing_provider, created_at
                        )
                        VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'pending', 'paddle', NOW())
                        "#,
                    )
                    .bind(&txn.id)
                    .bind(user_id)
                    .bind(format!("INV-{}", &txn.id[4..]))
                    .bind(remainder_cents)
                    .execute(&state.pool)
                    .await {
                        tracing::error!("Failed to insert paddle invoice for org {}: {}", org_id, e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to create Paddle transaction for org {}: {}", org_id, e);
                }
            }
        } else {
            tracing::warn!("Org {} has no paddle_customer_id, skipping billing", org_id);
        }
    }

    tracing::info!("Monthly billing cycle complete — Paddle will collect payments");

    Ok(())
}

/// Process subscription renewals — called on every hourly tick
async fn run_subscription_billing(state: &AppState) -> Result<()> {
    if !try_advisory_lock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await {
        tracing::debug!("Subscription billing skipped — another instance holds the lock");
        return Ok(());
    }
    let result = run_subscription_billing_inner(state).await;
    advisory_unlock(&state.pool, LOCK_SUBSCRIPTION_BILLING).await;
    result
}

async fn run_subscription_billing_inner(state: &AppState) -> Result<()> {
    let due_subs = sqlx::query(
        r#"
        SELECT id, user_id, organization_id, tier, billing_period,
               price_cents_per_cycle, extra_block_price_cents_per_cycle,
               cancel_at_period_end, status
        FROM subscriptions
        WHERE status IN ('active', 'past_due') AND next_billing_at <= NOW()
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    if due_subs.is_empty() {
        return Ok(());
    }

    tracing::info!("Processing {} due subscription renewals", due_subs.len());

    for row in &due_subs {
        let sub_id: uuid::Uuid = row.get("id");
        let user_id: uuid::Uuid = row.get("user_id");
        let org_id: uuid::Uuid = row.get("organization_id");
        let tier: String = row.get("tier");
        let billing_period: String = row.get("billing_period");
        let base_price: i64 = row.get("price_cents_per_cycle");
        let extra_price: i64 = row.get("extra_block_price_cents_per_cycle");
        let cancel_at_end: bool = row.get("cancel_at_period_end");
        // If flagged for cancellation, cancel now
        if cancel_at_end {
            sqlx::query("UPDATE subscriptions SET status = 'canceled', updated_at = NOW() WHERE id = $1")
                .bind(&sub_id)
                .execute(&state.pool)
                .await?;
            tracing::info!("Subscription {} canceled at period end", sub_id);
            continue;
        }

        let total_charge = base_price + extra_price;
        let now = chrono::Utc::now();
        let period_end = calculate_subscription_period_end(now, &billing_period);

        // Deduct credits first
        let (credits_applied, remainder_cents) = credits::apply_credit_deduction(
            &state.pool,
            user_id,
            total_charge,
            &format!("Subscription renewal: {} ({})", tier, billing_period),
            None,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Credit deduction failed for sub {}: {}", sub_id, e);
            (0, total_charge)
        });

        let mut paddle_txn_id: Option<String> = None;
        let mut event_status = if remainder_cents == 0 { "credits_covered" } else { "pending" };

        if remainder_cents > 0 {
            // Look up Paddle customer ID (billing_config is keyed by user_id, not org_id)
            let paddle_customer_id: Option<String> = sqlx::query(
                "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1"
            )
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?
            .and_then(|row| row.get::<Option<String>, _>("paddle_customer_id"));

            if let Some(customer_id) = paddle_customer_id {
                let line_items = vec![paddle::LineItem {
                    description: format!("{} subscription renewal ({})", tier, billing_period),
                    quantity: 1,
                    unit_price_amount: remainder_cents.to_string(),
                    unit_price_currency: "USD".to_string(),
                }];

                match state.paddle.create_transaction(&customer_id, line_items).await {
                    Ok(txn) => {
                        tracing::info!(
                            "Created Paddle transaction {} for sub {} renewal (${:.2}, credits ${:.2})",
                            txn.id, sub_id, remainder_cents as f64 / 100.0, credits_applied as f64 / 100.0
                        );
                        paddle_txn_id = Some(txn.id.clone());

                        // Record invoice
                        if let Err(e) = sqlx::query(
                            r#"
                            INSERT INTO invoices (
                                paddle_transaction_id, user_id, invoice_number,
                                amount_cents, currency, status, payment_status,
                                billing_provider, created_at
                            )
                            VALUES ($1, $2, $3, $4, 'USD', 'finalized', 'pending', 'paddle', NOW())
                            "#,
                        )
                        .bind(&txn.id)
                        .bind(&user_id)
                        .bind(format!("INV-SUB-{}", &txn.id[4..]))
                        .bind(remainder_cents)
                        .execute(&state.pool)
                        .await {
                            tracing::error!("Failed to insert sub invoice for sub {}: {}", sub_id, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Paddle charge failed for sub {}: {}", sub_id, e);
                        event_status = "payment_failed";
                        // Mark subscription as past_due
                        if let Err(e) = sqlx::query("UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1")
                            .bind(&sub_id)
                            .execute(&state.pool)
                            .await {
                            tracing::error!("Failed to mark sub {} as past_due: {}", sub_id, e);
                        }
                    }
                }
            } else {
                tracing::warn!("Sub {} org {} has no paddle_customer_id", sub_id, org_id);
                event_status = "payment_failed";
                if let Err(e) = sqlx::query("UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE id = $1")
                    .bind(&sub_id)
                    .execute(&state.pool)
                    .await {
                    tracing::error!("Failed to mark sub {} as past_due: {}", sub_id, e);
                }
            }
        } else {
            // Fully credit-covered: record credit-only invoice
            let invoice_number = format!("INV-SUB-CR-{}", &sub_id.to_string()[..8]);
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO invoices (
                    user_id, invoice_number, amount_cents, currency, status, payment_status, billing_provider, created_at, paid_at
                )
                VALUES ($1, $2, $3, 'USD', 'finalized', 'credits_applied', 'credits', NOW(), NOW())
                "#,
            )
            .bind(&user_id)
            .bind(&invoice_number)
            .bind(total_charge)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to insert credit-covered sub invoice for sub {}: {}", sub_id, e);
            }
        }

        // Record billing event
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO subscription_billing_events
            (subscription_id, user_id, billing_period_start, billing_period_end, tier,
             base_amount_cents, addon_amount_cents, total_amount_cents, credits_applied_cents, charged_amount_cents,
             paddle_transaction_id, status)
            VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&sub_id)
        .bind(&user_id)
        .bind(period_end)
        .bind(&tier)
        .bind(base_price)
        .bind(extra_price)
        .bind(total_charge)
        .bind(credits_applied)
        .bind(remainder_cents)
        .bind(&paddle_txn_id)
        .bind(event_status)
        .execute(&state.pool)
        .await {
            tracing::error!("Failed to record billing event for sub {}: {}", sub_id, e);
        }

        // Advance period (only if charge wasn't a total failure)
        if event_status != "payment_failed" {
            if let Err(e) = sqlx::query(
                "UPDATE subscriptions SET
                 current_period_start = current_period_end,
                 current_period_end = $1,
                 next_billing_at = $1,
                 last_billed_at = NOW(),
                 updated_at = NOW()
                 WHERE id = $2"
            )
            .bind(period_end)
            .bind(&sub_id)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to advance billing period for sub {}: {}", sub_id, e);
            }
        }
    }

    Ok(())
}

fn calculate_subscription_period_end(start: chrono::DateTime<chrono::Utc>, billing_period: &str) -> chrono::DateTime<chrono::Utc> {
    use chrono::{Datelike, NaiveDate};

    let add_months = match billing_period {
        "yearly" => 12,
        "2year"  => 24,
        _        => 1,
    };

    let total_months = start.month0() as i32 + add_months;
    let target_year = start.year() + total_months / 12;
    let target_month = (total_months % 12) as u32 + 1;

    // Clamp day to last day of target month to avoid panics (e.g. Jan 31 -> Feb 28)
    let last_day_of_target = NaiveDate::from_ymd_opt(
        target_year,
        if target_month == 12 { 1 } else { target_month + 1 },
        1,
    )
    .unwrap_or_else(|| NaiveDate::from_ymd_opt(target_year + 1, 1, 1).unwrap())
    .pred_opt()
    .unwrap()
    .day();

    let day = start.day().min(last_day_of_target);

    start
        .date_naive()
        .with_year(target_year).unwrap_or(start.date_naive())
        .with_month(target_month).unwrap_or(start.date_naive())
        .with_day(day).unwrap_or(start.date_naive())
        .and_time(start.time())
        .and_utc()
}

// Advisory lock IDs for distributed coordination
const LOCK_COLLECTION: i64 = 1001;
const LOCK_MONTHLY_BILLING: i64 = 1002;
const LOCK_SUBSCRIPTION_BILLING: i64 = 1003;

/// Try to acquire an advisory lock, run the closure, and release the lock.
/// Returns None if the lock is already held by another instance.
async fn try_advisory_lock(pool: &sqlx::PgPool, lock_id: i64) -> bool {
    sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(pool)
        .await
        .unwrap_or(false)
}

async fn advisory_unlock(pool: &sqlx::PgPool, lock_id: i64) {
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(pool)
        .await;
}

async fn run_collection_cycle(state: &AppState) -> Result<usize> {
    if !try_advisory_lock(&state.pool, LOCK_COLLECTION).await {
        tracing::debug!("Collection cycle skipped — another instance holds the lock");
        return Ok(0);
    }
    let result = run_collection_cycle_inner(state).await;
    advisory_unlock(&state.pool, LOCK_COLLECTION).await;
    result
}

async fn run_collection_cycle_inner(state: &AppState) -> Result<usize> {
    tracing::info!("Running metering collection cycle");

    let resources = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut collected = 0;
    let mut users_with_deductions = HashSet::new();

    for resource in &resources {
        match collect_resource_usage(state, &resource.resource_id).await {
            Ok(true) => {
                collected += 1;
                users_with_deductions.insert(resource.user_id);
            }
            Ok(false) => {
                collected += 1;
            }
            Err(e) => {
                tracing::error!("Failed to collect usage for {}: {}", resource.resource_id, e);
            }
        }
    }

    // After all resources processed: check balance thresholds per user
    for user_id in users_with_deductions {
        if let Err(e) = check_balance_thresholds(state, user_id).await {
            tracing::error!("Failed to check balance thresholds for {}: {}", user_id, e);
        }
    }

    tracing::info!("Collected usage for {} resources", collected);
    Ok(collected)
}

/// Collect usage for a resource and deduct credits in real-time.
/// Returns Ok(true) if a credit deduction occurred, Ok(false) if usage was recorded
/// but no deduction was needed (e.g. zero cost).
async fn collect_resource_usage(state: &AppState, resource_id: &str) -> Result<bool> {
    let resource = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE resource_id = $1
        "#,
    )
    .bind(resource_id)
    .fetch_optional(&state.pool)
    .await?
    .context("Resource not found")?;

    let now = time::OffsetDateTime::now_utc();
    let last_billed = resource.last_billed_at;

    // Calculate hours since last billing using unix timestamps
    let now_unix = now.unix_timestamp();
    let last_billed_unix = last_billed.unix_timestamp();
    let seconds_elapsed = (now_unix - last_billed_unix) as f64;
    let hours = seconds_elapsed / 3600.0;

    if hours < 0.01 {
        // Less than ~36 seconds, skip
        return Ok(false);
    }

    let provider: Provider = resource.provider.parse().unwrap_or(Provider::Aws);

    let usage = ResourceUsage {
        user_id: resource.user_id,
        resource_id: resource.resource_id.clone(),
        provider,
        resource_type: ResourceType::Compute,
        quantity: hours,
        unit: UsageUnit::Hours,
        timestamp: now,
        metadata: serde_json::json!({
            "instance_type": resource.instance_type,
            "region": resource.region,
        }),
    };

    let cost = state.calculator.calculate_cost(&usage);

    // Record locally
    sqlx::query(
        r#"
        INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(usage.user_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(cost)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await?;

    // Update last_billed_at
    sqlx::query(r#"UPDATE tracked_resources SET last_billed_at = $1 WHERE resource_id = $2"#)
        .bind(now)
        .bind(resource_id)
        .execute(&state.pool)
        .await?;

    tracing::debug!(
        "Recorded usage for {}: {:.4} hours, ${:.4}",
        resource_id, hours, cost
    );

    // Real-time credit deduction
    let cost_cents = (cost * 100.0).round() as i64;
    if cost_cents > 0 {
        let (_applied, _remainder, _new_balance) = credits::deduct_realtime_usage(
            &state.pool, resource.user_id, cost_cents, resource_id, hours
        ).await?;
        return Ok(true);
    }

    Ok(false)
}

// =============================================================================
// Balance threshold checks (pause / warn / auto-topup)
// =============================================================================

/// After deducting credits, check if the user's balance requires action.
async fn check_balance_thresholds(state: &AppState, user_id: uuid::Uuid) -> Result<()> {
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(0);

    // Read billing config for auto-topup settings
    let config = sqlx::query(
        r#"SELECT auto_topup_enabled, auto_topup_amount_dollars,
                  low_balance_warned_at, last_auto_topup_at, paddle_customer_id
           FROM billing_config WHERE user_id = $1"#
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let auto_topup_enabled = config.as_ref()
        .and_then(|r| r.get::<Option<bool>, _>("auto_topup_enabled"))
        .unwrap_or(false);
    let auto_topup_dollars: i32 = config.as_ref()
        .and_then(|r| r.get::<Option<i32>, _>("auto_topup_amount_dollars"))
        .unwrap_or(0);
    let low_balance_warned_at: Option<chrono::DateTime<chrono::Utc>> = config.as_ref()
        .and_then(|r| r.get("low_balance_warned_at"));
    let last_auto_topup_at: Option<chrono::DateTime<chrono::Utc>> = config.as_ref()
        .and_then(|r| r.get("last_auto_topup_at"));
    let paddle_customer_id: Option<String> = config.as_ref()
        .and_then(|r| r.get("paddle_customer_id"));

    // Look up user's org
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(org_id) = org_id else {
        return Ok(());
    };

    let now = chrono::Utc::now();

    // Priority 1: Balance <= 0 → suspend fully-managed resources + trigger auto-topup if enabled
    if balance_cents <= 0 {
        let already_suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT credit_suspended_at FROM organizations WHERE id = $1"
        )
        .bind(org_id)
        .fetch_optional(&state.pool)
        .await?
        .flatten();

        if already_suspended.is_none() {
            tracing::warn!("User {} balance {} <= 0, suspending fully-managed resources", user_id, balance_cents);
            suspend_fully_managed_org(state, org_id).await;
        }

        // If auto-topup is enabled, trigger it so the user can auto-recover after suspension
        if auto_topup_enabled && auto_topup_dollars > 0 {
            let target_cents = (auto_topup_dollars as i64) * 100;
            let cooldown_ok = last_auto_topup_at
                .map(|t| (now - t).num_seconds() > 300)
                .unwrap_or(true);
            if cooldown_ok {
                if let Some(customer_id) = paddle_customer_id.as_ref() {
                    tracing::info!("Triggering auto-topup for suspended user {} to enable recovery", user_id);
                    trigger_auto_topup(state, user_id, balance_cents, target_cents, customer_id).await;
                }
            }
        }

        return Ok(());
    }

    // Priority 2: Auto top-up enabled and balance < 5% of target (pre-emptive top-up)
    if auto_topup_enabled && auto_topup_dollars > 0 {
        let target_cents = (auto_topup_dollars as i64) * 100;
        let threshold = target_cents / 20; // 5%
        if balance_cents < threshold {
            let cooldown_ok = last_auto_topup_at
                .map(|t| (now - t).num_seconds() > 300)
                .unwrap_or(true);
            if cooldown_ok {
                if let Some(customer_id) = paddle_customer_id.as_ref() {
                    trigger_auto_topup(state, user_id, balance_cents, target_cents, customer_id).await;
                }
            }
        }
        return Ok(());
    }

    // Priority 3: No auto top-up, balance < $5 (500 cents) → warn
    if balance_cents < 500 {
        let cooldown_ok = low_balance_warned_at
            .map(|t| (now - t).num_seconds() > 86400) // >24h
            .unwrap_or(true);
        if cooldown_ok {
            tracing::info!("Low balance warning for user {} ({}c)", user_id, balance_cents);

            if let Err(e) = sqlx::query(
                "UPDATE billing_config SET low_balance_warned_at = NOW() WHERE user_id = $1"
            )
            .bind(user_id)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to update low_balance_warned_at for user {}: {}", user_id, e);
            }

            send_dunning_email(state, org_id, "insufficient_balance", serde_json::json!({
                "balance": format!("${:.2}", balance_cents as f64 / 100.0),
                "amount": format!("${:.2}", balance_cents as f64 / 100.0),
                "add_credits_url": "https://caution.dev/settings/billing",
            })).await;
        }
    }

    Ok(())
}

/// Suspend only fully-managed resources for an org (not managed on-prem).
async fn suspend_fully_managed_org(state: &AppState, org_id: uuid::Uuid) {
    // Set credit_suspended_at
    if let Err(e) = sqlx::query(
        "UPDATE organizations SET credit_suspended_at = NOW() WHERE id = $1 AND credit_suspended_at IS NULL"
    )
    .bind(org_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to set credit_suspended_at for org {}: {}", org_id, e);
    }

    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let Some(ref internal_secret) = state.internal_service_secret else {
        tracing::error!("INTERNAL_SERVICE_SECRET not configured — cannot call API to suspend managed resources for org {}", org_id);
        return;
    };

    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some(user_id) = user_id else {
        tracing::error!("No members found for org {}, cannot suspend", org_id);
        return;
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/internal/org/{}/suspend-managed", api_url, org_id))
        .header("x-internal-service-secret", internal_secret.as_str())
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Suspended fully-managed resources for org {}", org_id);

            send_dunning_email(state, org_id, "suspension_notice", serde_json::json!({
                "reason": "credit_exhaustion",
                "add_credits_url": "https://caution.dev/settings/billing",
            })).await;
        }
        Ok(r) => {
            tracing::error!("API returned {} when suspending managed resources for org {}", r.status(), org_id);
        }
        Err(e) => {
            tracing::error!("Failed to call API to suspend managed resources for org {}: {}", org_id, e);
        }
    }
}

/// Trigger auto top-up by creating a Paddle transaction for `target - current_balance`.
async fn trigger_auto_topup(
    state: &AppState,
    user_id: uuid::Uuid,
    current_balance: i64,
    target_cents: i64,
    paddle_customer_id: &str,
) {
    let topup_cents = target_cents - current_balance;
    if topup_cents <= 0 {
        return;
    }

    tracing::info!(
        "Auto top-up: user={}, current={}c, target={}c, charging={}c",
        user_id, current_balance, target_cents, topup_cents
    );

    // Optimistic: set last_auto_topup_at to prevent rapid-fire
    if let Err(e) = sqlx::query(
        "UPDATE billing_config SET last_auto_topup_at = NOW() WHERE user_id = $1"
    )
    .bind(user_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to set last_auto_topup_at for user {}: {}", user_id, e);
    }

    let topup_dollars = topup_cents as f64 / 100.0;
    let line_items = vec![paddle::LineItem {
        description: format!("Auto top-up: ${:.2}", topup_dollars),
        quantity: 1,
        unit_price_amount: format!("{}", topup_cents),
        unit_price_currency: "USD".to_string(),
    }];

    // Retry up to 3 times with exponential backoff
    let mut last_err = None;
    for attempt in 0..3 {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << attempt); // 2s, 4s
            tracing::info!("Auto top-up retry {} for user {} in {:?}", attempt + 1, user_id, delay);
            tokio::time::sleep(delay).await;
        }

        match state.paddle.create_transaction(paddle_customer_id, line_items.clone()).await {
            Ok(txn) => {
                tracing::info!(
                    "Created Paddle auto-topup transaction {} for user {} (${:.2})",
                    txn.id, user_id, topup_dollars
                );
                // Credits will be deposited when transaction.completed webhook fires
                return;
            }
            Err(e) => {
                tracing::warn!("Auto top-up attempt {} failed for user {}: {}", attempt + 1, user_id, e);
                last_err = Some(e);
            }
        }
    }

    // All retries exhausted — clear last_auto_topup_at so the next collection cycle can retry
    tracing::error!("Auto top-up failed after 3 attempts for user {}: {}", user_id, last_err.unwrap());
    if let Err(e) = sqlx::query(
        "UPDATE billing_config SET last_auto_topup_at = NULL WHERE user_id = $1"
    )
    .bind(user_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to clear last_auto_topup_at for user {}: {}", user_id, e);
    }

    // Send payment failure email
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    if let Some(org_id) = org_id {
        send_dunning_email(state, org_id, "payment_failure", serde_json::json!({
            "reason": "auto_topup_failed",
            "update_payment_url": "https://caution.dev/settings/billing",
        })).await;
    }
}

// =============================================================================
// Test Endpoints - For simulating billing flow without real infrastructure
// =============================================================================

#[derive(serde::Deserialize)]
struct TestSimulateUsageRequest {
    user_id: uuid::Uuid,
    hours: Option<f64>,
    instance_type: Option<String>,
}

/// Simulate resource usage for testing the billing pipeline
async fn test_simulate_usage(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulateUsageRequest>,
) -> impl IntoResponse {
    let hours = req.hours.unwrap_or(1.0);
    let instance_type = req.instance_type.unwrap_or_else(|| "m5.xlarge".to_string());
    let resource_id = format!("test-{}", uuid::Uuid::new_v4());

    let now = time::OffsetDateTime::now_utc();

    let usage = ResourceUsage {
        user_id: req.user_id,
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

    let cost = state.calculator.calculate_cost(&usage);

    // Record locally
    let result = sqlx::query(
        r#"
        INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(usage.user_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(cost)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!(
                "TEST: Simulated {} hours of {} usage for user {}, cost: ${:.4}",
                hours, instance_type, req.user_id, cost
            );

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "resource_id": resource_id,
                "hours": hours,
                "instance_type": instance_type,
                "cost_usd": cost,
                "message": "Usage recorded locally. Paddle transaction will be created at billing cycle end."
            })))
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": e.to_string()
            })))
        }
    }
}

#[derive(serde::Deserialize)]
struct TestSimulatePaddleTransactionRequest {
    user_id: uuid::Uuid,
    amount_cents: i64,
    #[serde(default)]
    event_type: Option<String>, // transaction.completed, transaction.billed, transaction.payment_failed
    #[serde(default)]
    transaction_id: Option<String>, // reuse a specific transaction ID (e.g. from a prior billed event)
}

/// Simulate a Paddle transaction webhook for testing email and billing flow
async fn test_simulate_paddle_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulatePaddleTransactionRequest>,
) -> impl IntoResponse {
    let transaction_id = req.transaction_id
        .unwrap_or_else(|| format!("txn_test_{}", uuid::Uuid::new_v4()));
    let event_type = req.event_type.unwrap_or_else(|| "transaction.billed".to_string());
    let invoice_number = format!("TEST-{}", &transaction_id[9..17].to_uppercase());

    // Ensure the user has a paddle_customer_id in billing_config
    let customer_id = format!("ctm_test_{}", req.user_id);
    if let Err(e) = sqlx::query(
        r#"
        UPDATE billing_config SET paddle_customer_id = $1 WHERE user_id = $2
        "#,
    )
    .bind(&customer_id)
    .bind(req.user_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to update paddle_customer_id for test user {}: {}", req.user_id, e);
    }

    // Build a fake Paddle webhook payload
    let payload = webhooks::PaddleWebhookPayload {
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
            }
        }),
    };

    tracing::info!(
        "TEST: Simulating Paddle {} for user {} (${:.2})",
        event_type,
        req.user_id,
        req.amount_cents as f64 / 100.0
    );

    match webhooks::handle_paddle_transaction_test(&state, payload).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "transaction_id": transaction_id,
                "event_type": event_type,
                "invoice_number": invoice_number,
                "amount_cents": req.amount_cents,
                "message": "Paddle transaction processed. Check email service logs for notifications."
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            })),
        ),
    }
}

// =============================================================================
// AWS Cost Explorer Endpoints
// =============================================================================

#[derive(serde::Deserialize)]
struct SyncAwsCostsRequest {
    /// Start date in YYYY-MM-DD format (defaults to first of current month)
    start_date: Option<String>,
    /// End date in YYYY-MM-DD format (defaults to today)
    end_date: Option<String>,
}

/// Sync costs from AWS Cost Explorer for all orgs and record as usage
async fn sync_aws_costs(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SyncAwsCostsRequest>,
) -> impl IntoResponse {
    // Get date range
    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = req.start_date.unwrap_or(default_start);
    let end_date = req.end_date.unwrap_or(default_end);

    tracing::info!("Syncing AWS costs from {} to {}", start_date, end_date);

    // Create Cost Explorer client
    let ce_client = match cost_explorer::CostExplorerClient::new().await {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create Cost Explorer client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to initialize AWS: {}", e)})),
            );
        }
    };

    // Get costs for all orgs
    let org_costs = match ce_client.get_all_org_costs(&start_date, &end_date).await {
        Ok(costs) => costs,
        Err(e) => {
            tracing::error!("Failed to fetch AWS costs: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to fetch costs: {}", e)})),
            );
        }
    };

    let mut synced_count = 0;
    let mut total_cost = 0.0;

    // Record each org's costs
    for (org_id, cost_data) in &org_costs {
        // Try to parse org_id as UUID (it should be the user/org UUID)
        let user_id: uuid::Uuid = match org_id.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!("Skipping non-UUID org_id: {}", org_id);
                continue;
            }
        };

        // Record in our usage table
        let now = time::OffsetDateTime::now_utc();
        let result = sqlx::query(
            r#"
            INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
            VALUES ($1, $2, 'aws', 'aws_cost_explorer', $3, 'usd', $3, $4, $5)
            "#,
        )
        .bind(user_id)
        .bind(format!("aws-costs-{}-{}", start_date, end_date))
        .bind(cost_data.total_cost)
        .bind(now)
        .bind(serde_json::json!({
            "source": "aws_cost_explorer",
            "start_date": start_date,
            "end_date": end_date,
            "services": cost_data.costs_by_service,
        }))
        .execute(&state.pool)
        .await;

        match result {
            Ok(_) => {
                synced_count += 1;
                total_cost += cost_data.total_cost;
                tracing::info!(
                    "Synced costs for org {}: ${:.2}",
                    org_id,
                    cost_data.total_cost
                );
            }
            Err(e) => {
                tracing::error!("Failed to record costs for org {}: {}", org_id, e);
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "synced_orgs": synced_count,
            "total_cost": total_cost,
            "period": {
                "start": start_date,
                "end": end_date,
            },
            "org_costs": org_costs,
        })),
    )
}

#[derive(serde::Deserialize)]
struct GetAwsCostsQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

/// Get AWS costs for a specific org
async fn get_aws_org_costs(
    Path(org_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> impl IntoResponse {
    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = match cost_explorer::CostExplorerClient::new().await {
        Ok(client) => client,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to initialize AWS: {}", e)})),
            );
        }
    };

    match ce_client.get_org_costs(&org_id, &start_date, &end_date).await {
        Ok(cost_data) => (StatusCode::OK, Json(serde_json::json!(cost_data))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Get AWS costs for all orgs (summary)
async fn get_all_aws_costs(
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> impl IntoResponse {
    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = match cost_explorer::CostExplorerClient::new().await {
        Ok(client) => client,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to initialize AWS: {}", e)})),
            );
        }
    };

    match ce_client.get_all_org_costs(&start_date, &end_date).await {
        Ok(org_costs) => {
            let total: f64 = org_costs.values().map(|c| c.total_cost).sum();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "period": {
                        "start": start_date,
                        "end": end_date,
                    },
                    "total_cost": total,
                    "org_count": org_costs.len(),
                    "orgs": org_costs,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Manually trigger monthly billing (for testing or catch-up)
async fn trigger_monthly_billing(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    tracing::info!("Manually triggering monthly billing cycle");

    match run_monthly_billing_cycle(&state).await {
        Ok(()) => {
            let (start, end) = cost_explorer::previous_month_billing_period();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "success",
                    "message": "Monthly billing cycle completed",
                    "billing_period": {
                        "start": start,
                        "end": end,
                    }
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// =============================================================================
// Billing Estimate (User-facing dashboard)
// =============================================================================

/// Get billing estimate for an org - current spend + projected end-of-month
async fn get_billing_estimate(
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let now = time::OffsetDateTime::now_utc();
    let today = now.date();

    // Get current billing period (first of month to today)
    let (start_date, end_date) = cost_explorer::current_billing_period();

    // Calculate days elapsed and remaining
    let first_of_month = time::Date::from_calendar_date(today.year(), today.month(), 1)
        .expect("valid date");
    let days_elapsed = (today - first_of_month).whole_days() + 1; // +1 to include today
    let days_in_month = days_in_month(today.year(), today.month());
    let days_remaining = days_in_month - days_elapsed as u8;

    // Fetch current costs from AWS
    let ce_client = match cost_explorer::CostExplorerClient::new().await {
        Ok(client) => client,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to initialize AWS: {}", e)})),
            );
        }
    };

    let cost_data = match ce_client.get_org_costs(&org_id, &start_date, &end_date).await {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    // Calculate projections
    let current_spend = cost_data.total_cost;
    let daily_average = if days_elapsed > 0 {
        current_spend / days_elapsed as f64
    } else {
        0.0
    };
    let projected_remaining = daily_average * days_remaining as f64;
    let projected_total = current_spend + projected_remaining;

    // Round for display
    let current_spend = (current_spend * 100.0).round() / 100.0;
    let daily_average = (daily_average * 100.0).round() / 100.0;
    let projected_total = (projected_total * 100.0).round() / 100.0;

    // Determine spend trend (compare to previous period if available)
    let spend_trend = if daily_average > 0.0 { "active" } else { "idle" };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "org_id": org_id,
            "billing_period": {
                "start": start_date,
                "end": format!("{}-{:02}-{:02}",
                    today.year(),
                    today.month() as u8,
                    days_in_month
                ),
                "days_elapsed": days_elapsed,
                "days_remaining": days_remaining,
                "days_in_month": days_in_month,
            },
            "current_spend": {
                "amount": current_spend,
                "currency": "USD",
                "as_of": end_date,
            },
            "projection": {
                "daily_average": daily_average,
                "estimated_remaining": (projected_remaining * 100.0).round() / 100.0,
                "estimated_total": projected_total,
                "currency": "USD",
            },
            "breakdown_by_service": cost_data.costs_by_service,
            "trend": spend_trend,
        })),
    )
}

/// Get the number of days in a month
fn days_in_month(year: i32, month: time::Month) -> u8 {
    let next_month = match month {
        time::Month::December => time::Month::January,
        _ => month.next(),
    };
    let next_year = if month == time::Month::December {
        year + 1
    } else {
        year
    };

    let first_of_next = time::Date::from_calendar_date(next_year, next_month, 1)
        .expect("valid date");
    let first_of_current = time::Date::from_calendar_date(year, month, 1)
        .expect("valid date");

    (first_of_next - first_of_current).whole_days() as u8
}

// ---------------------------------------------------------------------------
// Dunning enforcement loop
// ---------------------------------------------------------------------------

/// Runs every hour. Detects delinquent orgs, sends escalating emails, and
/// suspends resources after 7 days of non-payment.
async fn run_dunning_loop(state: Arc<AppState>) {
    // Check every hour
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    loop {
        interval.tick().await;
        if let Err(e) = run_dunning_cycle(&state).await {
            tracing::error!("Dunning cycle failed: {}", e);
        }
    }
}

async fn run_dunning_cycle(state: &AppState) -> Result<()> {
    // 1. Detect orgs with past_due subscriptions that don't have payment_failed_at set yet
    let newly_delinquent: Vec<(uuid::Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT s.organization_id
        FROM subscriptions s
        JOIN organizations o ON o.id = s.organization_id
        WHERE s.status = 'past_due'
          AND o.payment_failed_at IS NULL
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for (org_id,) in &newly_delinquent {
        tracing::info!("Marking org {} as payment-failed", org_id);
        sqlx::query(
            "UPDATE organizations SET payment_failed_at = NOW(), dunning_stage = 'none' WHERE id = $1"
        )
        .bind(org_id)
        .execute(&state.pool)
        .await?;
    }

    // 2. Also detect fully-managed orgs with negative wallet balance and no payment method
    let negative_balance_orgs: Vec<(uuid::Uuid,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT o.id
        FROM organizations o
        JOIN organization_members om ON om.organization_id = o.id
        JOIN wallet_balance wb ON wb.user_id = om.user_id
        WHERE wb.balance_cents < 0
          AND o.payment_failed_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM payment_methods pm
              WHERE pm.organization_id = o.id AND pm.is_active = true
          )
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    for (org_id,) in &negative_balance_orgs {
        tracing::info!("Marking org {} as payment-failed (negative balance, no payment method)", org_id);
        sqlx::query(
            "UPDATE organizations SET payment_failed_at = NOW(), dunning_stage = 'none' WHERE id = $1"
        )
        .bind(org_id)
        .execute(&state.pool)
        .await?;
    }

    // 3. Process orgs that are in dunning (exclude credit-suspended orgs — handled by real-time system)
    let delinquent_orgs: Vec<(uuid::Uuid, chrono::DateTime<chrono::Utc>, String)> = sqlx::query_as(
        r#"
        SELECT id, payment_failed_at, dunning_stage
        FROM organizations
        WHERE payment_failed_at IS NOT NULL
          AND credit_suspended_at IS NULL
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    if delinquent_orgs.is_empty() {
        return Ok(());
    }

    tracing::info!("Processing {} delinquent orgs", delinquent_orgs.len());

    let now = chrono::Utc::now();

    for (org_id, failed_at, stage) in &delinquent_orgs {
        // Check if the org has resolved payment (subscription back to active, or balance >= 0 with payment method)
        let is_resolved = check_payment_resolved(&state.pool, *org_id).await.unwrap_or(false);

        if is_resolved {
            tracing::info!("Org {} has resolved payment, clearing dunning", org_id);

            if stage == "suspended" {
                // Unsuspend: call API to restart instances
                unsuspend_org(&state, *org_id).await;
            }

            sqlx::query(
                "UPDATE organizations SET payment_failed_at = NULL, dunning_stage = 'none' WHERE id = $1"
            )
            .bind(org_id)
            .execute(&state.pool)
            .await?;
            continue;
        }

        let days_overdue = (now - *failed_at).num_days();

        match stage.as_str() {
            "none" => {
                // Day 0: send initial payment failure email
                send_dunning_email(&state, *org_id, "payment_failure", serde_json::json!({
                    "update_payment_url": "https://caution.dev/settings/billing",
                })).await;

                sqlx::query("UPDATE organizations SET dunning_stage = 'warning_sent' WHERE id = $1")
                    .bind(org_id)
                    .execute(&state.pool)
                    .await?;
            }
            "warning_sent" if days_overdue >= 3 => {
                // Day 3: send suspension warning
                send_dunning_email(&state, *org_id, "suspension_warning", serde_json::json!({
                    "days_remaining": 4,
                    "amount": "your outstanding balance",
                })).await;

                sqlx::query("UPDATE organizations SET dunning_stage = 'reminder_sent' WHERE id = $1")
                    .bind(org_id)
                    .execute(&state.pool)
                    .await?;
            }
            "reminder_sent" if days_overdue >= 7 => {
                // Day 7: suspend resources
                tracing::warn!("Org {} overdue for {} days, suspending resources", org_id, days_overdue);
                suspend_org(&state, *org_id).await;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Check if an org has resolved its payment issues.
async fn check_payment_resolved(pool: &sqlx::PgPool, org_id: uuid::Uuid) -> Result<bool> {
    // Check if all subscriptions are active (not past_due)
    let has_past_due: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE organization_id = $1 AND status = 'past_due')"
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;

    if has_past_due {
        return Ok(false);
    }

    // For fully managed: check they have a payment method or positive balance
    let has_payment_method: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payment_methods WHERE organization_id = $1 AND is_active = true)"
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;

    if has_payment_method {
        return Ok(true);
    }

    // Check if any member has positive wallet balance
    let has_balance: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM organization_members om
            JOIN wallet_balance wb ON wb.user_id = om.user_id
            WHERE om.organization_id = $1 AND wb.balance_cents >= 0
        )
        "#
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;

    Ok(has_balance)
}

/// Call the API service to suspend all running resources for an org.
async fn suspend_org(state: &AppState, org_id: uuid::Uuid) {
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let Some(ref internal_secret) = state.internal_service_secret else {
        tracing::error!("INTERNAL_SERVICE_SECRET not configured — cannot call API to suspend org {}", org_id);
        return;
    };
    // We need a user_id for internal auth — use any org member
    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some(user_id) = user_id else {
        tracing::error!("No members found for org {}, cannot suspend", org_id);
        return;
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/internal/org/{}/suspend", api_url, org_id))
        .header("x-internal-service-secret", internal_secret.as_str())
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Successfully suspended org {}", org_id);
            // Send suspension notice email
            let app_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM compute_resources WHERE organization_id = $1 AND state = 'stopped'"
            )
            .bind(org_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

            send_dunning_email(state, org_id, "suspension_notice", serde_json::json!({
                "amount": "your outstanding balance",
                "app_count": app_count,
            })).await;
        }
        Ok(r) => {
            tracing::error!("API returned {} when suspending org {}", r.status(), org_id);
        }
        Err(e) => {
            tracing::error!("Failed to call API to suspend org {}: {}", org_id, e);
        }
    }
}

/// Call the API service to unsuspend (restart) stopped resources for an org.
async fn unsuspend_org(state: &AppState, org_id: uuid::Uuid) {
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let Some(ref internal_secret) = state.internal_service_secret else {
        tracing::error!("INTERNAL_SERVICE_SECRET not configured — cannot call API to unsuspend org {}", org_id);
        return;
    };

    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some(user_id) = user_id else {
        tracing::error!("No members found for org {}, cannot unsuspend", org_id);
        return;
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/internal/org/{}/unsuspend", api_url, org_id))
        .header("x-internal-service-secret", internal_secret.as_str())
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Successfully unsuspended org {}", org_id);
        }
        Ok(r) => {
            tracing::error!("API returned {} when unsuspending org {}", r.status(), org_id);
        }
        Err(e) => {
            tracing::error!("Failed to call API to unsuspend org {}: {}", org_id, e);
        }
    }
}

/// Send a dunning email to all members of an org.
async fn send_dunning_email(state: &AppState, org_id: uuid::Uuid, template: &str, data: serde_json::Value) {
    let members: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT u.email FROM users u
        JOIN organization_members om ON om.user_id = u.id
        WHERE om.organization_id = $1 AND u.email IS NOT NULL
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());
    let client = reqwest::Client::new();

    for (email,) in &members {
        let email_request = serde_json::json!({
            "to": email,
            "template": template,
            "data": data,
        });

        let _ = client
            .post(format!("{}/send", email_service_url))
            .json(&email_request)
            .send()
            .await;

        tracing::info!("Sent {} email to {} for org {}", template, email, org_id);
    }
}

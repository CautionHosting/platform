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
use std::collections::HashMap;
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

mod balance;
mod billing;
mod collection;
mod dunning;

use types::*;

pub struct AppState {
    pub pool: sqlx::PgPool,
    pub paddle: paddle::PaddleClient,
    pub calculator: calculator::CostCalculator,
    pub cloudwatch: aws_sdk_cloudwatch::Client,
    pub internal_service_secret: String,
}

fn load_internal_service_secret() -> Result<String> {
    std::env::var("INTERNAL_SERVICE_SECRET")
        .ok()
        .map(|secret| secret.trim().to_string())
        .filter(|secret| !secret.is_empty())
        .context("INTERNAL_SERVICE_SECRET must be set for the metering service")
}

fn has_valid_internal_service_secret(
    configured_secret: &str,
    provided_secret: Option<&str>,
) -> bool {
    matches!(provided_secret, Some(secret) if secret == configured_secret)
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

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

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

    let internal_service_secret = load_internal_service_secret()?;

    let paddle = paddle::PaddleClient::new(paddle_api_url, paddle_api_key, paddle_webhook_secret);
    let calculator = calculator::CostCalculator::new(calculator::PricingRules::default());

    let aws_config = aws_config::load_from_env().await;
    let cloudwatch = aws_sdk_cloudwatch::Client::new(&aws_config);

    let state = Arc::new(AppState {
        pool,
        paddle,
        calculator,
        cloudwatch,
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
            let result = std::panic::AssertUnwindSafe(collection::run_collection_loop(
                collection_state.clone(),
                collection_interval_secs,
            ));
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
            let result = std::panic::AssertUnwindSafe(billing::run_monthly_billing_loop(
                billing_state.clone(),
            ));
            if let Err(e) = futures::FutureExt::catch_unwind(result).await {
                tracing::error!(
                    "Monthly billing loop panicked: {:?}. Restarting in 60s...",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    // Start dunning enforcement loop (checks every hour)
    let dunning_state = state.clone();
    tokio::spawn(async move {
        loop {
            let result =
                std::panic::AssertUnwindSafe(dunning::run_dunning_loop(dunning_state.clone()));
            if let Err(e) = futures::FutureExt::catch_unwind(result).await {
                tracing::error!("Dunning loop panicked: {:?}. Restarting in 60s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    let enable_test_endpoints = std::env::var("ENABLE_TEST_ENDPOINTS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if enable_test_endpoints {
        let env = std::env::var("ENVIRONMENT").unwrap_or_default();
        if env == "production" {
            eprintln!("FATAL: ENABLE_TEST_ENDPOINTS is set in a production environment. Refusing to start.");
            std::process::exit(1);
        }
    }

    // Authenticated API routes — require a valid INTERNAL_SERVICE_SECRET header
    let mut api_routes = Router::new()
        .route("/api/resources/track", post(track_resource))
        .route(
            "/api/resources/{resource_id}/untrack",
            post(untrack_resource),
        )
        .route("/api/resources", get(list_tracked_resources))
        .route("/api/usage/{user_id}", get(get_user_usage))
        .route("/api/collect", post(collection::trigger_collection))
        // AWS Cost Explorer endpoints
        .route("/api/aws/costs/sync", post(sync_aws_costs))
        .route("/api/aws/costs/{org_id}", get(get_aws_org_costs))
        .route("/api/aws/costs", get(get_all_aws_costs))
        // Monthly billing
        .route(
            "/api/billing/monthly",
            post(billing::trigger_monthly_billing),
        )
        // User-facing billing dashboard
        .route(
            "/api/billing/estimate/{org_id}",
            get(billing::get_billing_estimate),
        );

    // Test endpoints: only available when ENABLE_TEST_ENDPOINTS=true
    if enable_test_endpoints {
        tracing::warn!("Test endpoints enabled — do NOT use in production");
        api_routes = api_routes
            .route("/test/simulate-usage", post(test_simulate_usage))
            .route(
                "/test/simulate-paddle-transaction",
                post(test_simulate_paddle_transaction),
            );
    }

    let api_routes = api_routes.layer(middleware::from_fn_with_state(
        state.clone(),
        internal_auth_middleware,
    ));

    // Webhook rate limiter: 30 requests per minute per IP
    let webhook_limiter = RateLimiter::new(30, std::time::Duration::from_secs(60));

    // Public routes — no auth required (health check, webhooks have their own signature verification)
    let webhook_routes = Router::new()
        .route("/webhooks/paddle", post(webhooks::paddle_webhook_handler))
        .layer(middleware::from_fn_with_state(
            webhook_limiter,
            webhook_rate_limit_middleware,
        ));

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
                entries
                    .last()
                    .map_or(false, |t| now.duration_since(*t) < self.window)
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
    let ip = req
        .headers()
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
async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let provided = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());

    if has_valid_internal_service_secret(&state.internal_service_secret, provided) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or missing internal service secret",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{has_valid_internal_service_secret, load_internal_service_secret};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn load_internal_service_secret_accepts_non_empty_value() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "super-secret");
        }
        let secret = load_internal_service_secret().expect("secret should load");
        assert_eq!(secret, "super-secret");
    }

    #[test]
    fn load_internal_service_secret_rejects_missing_value() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe {
            std::env::remove_var("INTERNAL_SERVICE_SECRET");
        }
        let err = load_internal_service_secret().expect_err("missing secret should fail");
        assert!(err
            .to_string()
            .contains("INTERNAL_SERVICE_SECRET must be set"));
    }

    #[test]
    fn load_internal_service_secret_rejects_empty_value() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "   ");
        }
        let err = load_internal_service_secret().expect_err("empty secret should fail");
        assert!(err
            .to_string()
            .contains("INTERNAL_SERVICE_SECRET must be set"));
    }

    #[test]
    fn has_valid_internal_service_secret_requires_exact_match() {
        assert!(has_valid_internal_service_secret("secret", Some("secret")));
        assert!(!has_valid_internal_service_secret("secret", Some("wrong")));
        assert!(!has_valid_internal_service_secret("secret", None));
    }
}

#[derive(serde::Deserialize)]
struct TrackResourceRequest {
    resource_id: String,
    organization_id: uuid::Uuid,
    #[serde(default)]
    user_id: Option<uuid::Uuid>,
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
        INSERT INTO tracked_resources (resource_id, organization_id, user_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'running', NOW(), NOW())
        ON CONFLICT (resource_id) DO UPDATE SET
            status = 'running',
            started_at = COALESCE(tracked_resources.started_at, NOW()),
            last_billed_at = COALESCE(tracked_resources.last_billed_at, NOW())
        "#,
    )
    .bind(&req.resource_id)
    .bind(req.organization_id)
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
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "tracking"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to track resource: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

async fn untrack_resource(
    State(state): State<Arc<AppState>>,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    // First collect any remaining usage before stopping tracking
    if let Err(e) = collection::collect_resource_usage(&state, &resource_id).await {
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
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "stopped"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to untrack resource: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

async fn list_tracked_resources(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let result = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, organization_id, user_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        ORDER BY started_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await;

    match result {
        Ok(resources) => (
            StatusCode::OK,
            Json(serde_json::json!({"resources": resources})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
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
            let usage: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "provider": row.get::<String, _>("provider"),
                        "resource_type": row.get::<String, _>("resource_type"),
                        "total_quantity": row.get::<Option<f64>, _>("total_quantity"),
                        "total_cost": row.get::<Option<f64>, _>("total_cost"),
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({"usage": usage})))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// =============================================================================
// Test Endpoints - For simulating billing flow without real infrastructure
// =============================================================================

#[derive(serde::Deserialize)]
struct TestSimulateUsageRequest {
    user_id: uuid::Uuid,
    organization_id: Option<uuid::Uuid>,
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

    let cost = state.calculator.calculate_cost(&usage);

    // Record locally
    let result = sqlx::query(
        r#"
        INSERT INTO usage_records (organization_id, user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(usage.organization_id)
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
                hours,
                instance_type,
                req.user_id,
                cost
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "success",
                    "resource_id": resource_id,
                    "hours": hours,
                    "instance_type": instance_type,
                    "cost_usd": cost,
                    "message": "Usage recorded locally. Paddle transaction will be created at billing cycle end."
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            })),
        ),
    }
}

#[derive(serde::Deserialize)]
struct TestSimulatePaddleTransactionRequest {
    user_id: uuid::Uuid,
    #[serde(default)]
    organization_id: Option<uuid::Uuid>,
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
    let transaction_id = req
        .transaction_id
        .unwrap_or_else(|| format!("txn_test_{}", uuid::Uuid::new_v4()));
    let event_type = req
        .event_type
        .unwrap_or_else(|| "transaction.billed".to_string());
    let invoice_number = format!("TEST-{}", &transaction_id[9..17].to_uppercase());

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
        let parsed_org_id: uuid::Uuid = match org_id.parse() {
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
            INSERT INTO usage_records (organization_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
            VALUES ($1, $2, 'aws', 'aws_cost_explorer', $3, 'usd', $3, $4, $5)
            "#,
        )
        .bind(parsed_org_id)
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

    match ce_client
        .get_org_costs(&org_id, &start_date, &end_date)
        .await
    {
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

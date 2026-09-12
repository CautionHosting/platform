// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BILLING_URL: &str = "https://dashboard.caution.co/#billing";

mod calculator;
mod cost_explorer;
mod credits;
mod paddle;
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
    pub pricing: caution_config::pricing::PricingConfig,
    pub cloudwatch: aws_sdk_cloudwatch::Client,
    pub internal_service_secret: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LoadSecretError {
    #[error("INTERNAL_SERVICE_SECRET must be set for the metering service [{location}]")]
    Missing { location: dterror::Location },
}

#[tracing::instrument(skip_all, err)]
fn load_internal_service_secret() -> Result<String, LoadSecretError> {
    std::env::var("INTERNAL_SERVICE_SECRET")
        .ok()
        .map(|secret| secret.trim().to_string())
        .filter(|secret| !secret.is_empty())
        .ok_or(LoadSecretError::Missing {
            location: std::panic::Location::caller(),
        })
}

#[tracing::instrument(skip_all)]
fn has_valid_internal_service_secret(
    configured_secret: &str,
    provided_secret: Option<&str>,
) -> bool {
    matches!(provided_secret, Some(secret) if secret == configured_secret)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("FATAL: DATABASE_URL must be set");
        std::process::exit(1);
    });

    let paddle_api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
    let paddle_api_key = std::env::var("PADDLE_API_KEY").unwrap_or_default();
    let paddle_webhook_secret = std::env::var("PADDLE_WEBHOOK_SECRET").unwrap_or_default();

    if !paddle_api_key.is_empty() && paddle_api_url.is_empty() {
        eprintln!(
            "FATAL: PADDLE_API_KEY is set but PADDLE_API_URL is not — set PADDLE_API_URL to the Paddle API base URL (e.g. https://sandbox-api.paddle.com or https://api.paddle.com)"
        );
        std::process::exit(1);
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("FATAL: Failed to connect to database: {e}");
            std::process::exit(1);
        });

    tracing::info!("Connected to database");

    let internal_service_secret = load_internal_service_secret().unwrap_or_else(|e| {
        eprintln!("FATAL: {e}");
        std::process::exit(1);
    });

    let paddle = paddle::PaddleClient::new(paddle_api_url, paddle_api_key, paddle_webhook_secret);
    let pricing_contents = std::fs::read_to_string("prices.json").unwrap_or_else(|e| {
        eprintln!("FATAL: prices.json not found. Configure explicit pricing before starting metering: {e}");
        std::process::exit(1);
    });
    let paddle_subscriptions_enabled = std::env::var("BYOC_PADDLE_SUBSCRIPTIONS_ENABLED")
        .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
    let pricing = caution_config::pricing::PricingConfig::parse(
        &pricing_contents,
        paddle_subscriptions_enabled,
    )
    .unwrap_or_else(|e| {
        eprintln!("FATAL: Failed to parse prices.json for Paddle subscription processing: {e}");
        std::process::exit(1);
    });
    let calculator = calculator::CostCalculator::new(
        calculator::PricingRules::load()
            .unwrap_or_else(|e| {
                eprintln!("FATAL: Failed to load pricing rules: {e}");
                std::process::exit(1);
            }),
    );

    let aws_config = aws_config::load_from_env().await;
    let cloudwatch = aws_sdk_cloudwatch::Client::new(&aws_config);

    let state = Arc::new(AppState {
        pool,
        paddle,
        calculator,
        pricing,
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
            eprintln!(
                "FATAL: ENABLE_TEST_ENDPOINTS is set in a production environment. Refusing to start."
            );
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

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("FATAL: Failed to bind listener on {addr}: {e}");
        std::process::exit(1);
    });
    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("FATAL: Server error: {e}");
        std::process::exit(1);
    });
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
                    .is_some_and(|t| now.duration_since(*t) < self.window)
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
///
/// `x-forwarded-for` is trustworthy here because metering is not reachable
/// directly from the internet — the gateway is the only caller and it
/// overwrites this header with the real peer IP (see
/// `gateway::proxy::metering_proxy_handler`), discarding whatever the original
/// client sent. Without that, this header would be client-controlled and every
/// caller could collapse into the same rate-limit bucket.
#[tracing::instrument(skip_all)]
async fn webhook_rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next_back())
        .unwrap_or("unknown")
        .trim()
        .to_string();

    if !limiter.check(&ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    next.run(req).await
}

/// Internal service auth middleware — checks x-internal-service-secret header.
#[tracing::instrument(skip_all)]
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

// =============================================================================
// Handler error types
// =============================================================================

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TrackResourceError {
    #[error("could not track resource [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TrackResourceError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "track resource error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UntrackResourceError {
    #[error("could not untrack resource [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UntrackResourceError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "untrack resource error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListTrackedResourcesError {
    #[error("could not list tracked resources [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListTrackedResourcesError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "list tracked resources error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetUserUsageError {
    #[error("could not get user usage [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetUserUsageError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get user usage error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SyncAwsCostsError {
    #[error("could not sync AWS costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SyncAwsCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "sync AWS costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAwsOrgCostsError {
    #[error("could not get AWS org costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetAwsOrgCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get AWS org costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAllAwsCostsError {
    #[error("could not get all AWS costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetAllAwsCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get all AWS costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TestSimulateUsageError {
    #[error("no pricing configured for resource type '{resource_type}' [{location}]")]
    NoPricing {
        resource_type: String,
        location: Location,
    },
    #[error("could not record simulated usage [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TestSimulateUsageError {
    fn into_response(self) -> Response {
        let err = &self;
        match self {
            Self::NoPricing { .. } => {
                tracing::error!(?err, "test simulate usage: no pricing");
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "no pricing configured for this resource type"})),
                )
                    .into_response()
            }
            Self::Database { .. } => {
                tracing::error!(?err, "test simulate usage: database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TestSimulatePaddleTransactionError {
    #[error("could not process paddle transaction [{location}]")]
    Webhook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TestSimulatePaddleTransactionError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "test simulate paddle transaction error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

// =============================================================================
// Handlers
// =============================================================================

#[derive(serde::Deserialize)]
struct TrackResourceRequest {
    resource_id: String,
    organization_id: uuid::Uuid,
    #[serde(default)]
    user_id: Option<uuid::Uuid>,
    #[serde(default)]
    application_id: Option<uuid::Uuid>,
    provider: Provider,
    instance_type: Option<String>,
    region: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[tracing::instrument(skip_all, err, fields(resource_id = %req.resource_id))]
async fn track_resource(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrackResourceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TrackResourceError> {
    use TrackResourceErrorCtx as Ctx;

    let metadata = req.metadata.unwrap_or(serde_json::json!({}));

    sqlx::query(
        r#"
        INSERT INTO tracked_resources (resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running', NOW(), NOW())
        ON CONFLICT (resource_id) DO UPDATE SET
            organization_id = EXCLUDED.organization_id,
            user_id = COALESCE(EXCLUDED.user_id, tracked_resources.user_id),
            application_id = COALESCE(EXCLUDED.application_id, tracked_resources.application_id),
            provider = EXCLUDED.provider,
            instance_type = COALESCE(EXCLUDED.instance_type, tracked_resources.instance_type),
            region = COALESCE(EXCLUDED.region, tracked_resources.region),
            metadata = EXCLUDED.metadata,
            status = 'running',
            started_at = CASE
                WHEN tracked_resources.status = 'running' THEN tracked_resources.started_at
                ELSE NOW()
            END,
            stopped_at = NULL,
            last_billed_at = CASE
                WHEN tracked_resources.status = 'running' THEN tracked_resources.last_billed_at
                ELSE NOW()
            END
        "#,
    )
    .bind(&req.resource_id)
    .bind(req.organization_id)
    .bind(req.user_id)
    .bind(req.application_id)
    .bind(req.provider.as_str())
    .bind(&req.instance_type)
    .bind(&req.region)
    .bind(&metadata)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!("Now tracking resource: {}", req.resource_id);
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "tracking"})),
    ))
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
async fn untrack_resource(
    State(state): State<Arc<AppState>>,
    Path(resource_id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), UntrackResourceError> {
    use UntrackResourceErrorCtx as Ctx;

    if let Err(e) =
        collection::collect_resource_usage(&state, &resource_id, std::time::Duration::ZERO).await
    {
        tracing::warn!("Failed to collect final usage for {}: {}", resource_id, e);
    }

    sqlx::query(
        r#"
        UPDATE tracked_resources
        SET status = 'stopped', stopped_at = NOW()
        WHERE resource_id = $1
        "#,
    )
    .bind(&resource_id)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!("Stopped tracking resource: {}", resource_id);
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "stopped"})),
    ))
}

#[tracing::instrument(skip_all, err)]
async fn list_tracked_resources(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<serde_json::Value>), ListTrackedResourcesError> {
    use ListTrackedResourcesErrorCtx as Ctx;

    let resources = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        ORDER BY started_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .with_context(Ctx::database())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"resources": resources})),
    ))
}

#[tracing::instrument(skip_all, err, fields(user_id = %user_id))]
async fn get_user_usage(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetUserUsageError> {
    use GetUserUsageErrorCtx as Ctx;

    let rows = sqlx::query(
        r#"
        SELECT
            provider,
            resource_type,
            quantity::float8           AS quantity,
            base_unit_cost_usd::float8 AS base_unit_cost_usd,
            margin_percent::float8     AS margin_percent
        FROM usage_ledger
        WHERE user_id = $1
        AND recorded_at >= NOW() - INTERVAL '30 days'
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .with_context(Ctx::database())?;

    let mut usage_map = std::collections::BTreeMap::<(String, String), (f64, f64)>::new();

    for row in &rows {
        let provider = row.get::<String, _>("provider");
        let resource_type = row.get::<String, _>("resource_type");
        let quantity = row.get::<f64, _>("quantity");
        let base_unit_cost_usd = row.get::<f64, _>("base_unit_cost_usd");
        let margin_percent = row.get::<f64, _>("margin_percent");
        let total_cost = crate::calculator::PricingBreakdown {
            base_unit_cost_usd,
            margin_percent,
        }
        .total_cost_usd(quantity);

        let entry = usage_map
            .entry((provider, resource_type))
            .or_insert((0.0, 0.0));
        entry.0 += quantity;
        entry.1 += total_cost;
    }

    let usage: Vec<serde_json::Value> = usage_map
        .into_iter()
        .map(|((provider, resource_type), (total_quantity, total_cost))| {
            serde_json::json!({
                "provider": provider,
                "resource_type": resource_type,
                "total_quantity": total_quantity,
                "total_cost": total_cost,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(serde_json::json!({"usage": usage}))))
}

// =============================================================================
// Test Endpoints - For simulating billing flow without real infrastructure
// =============================================================================

#[derive(serde::Deserialize)]
struct TestSimulateUsageRequest {
    user_id: uuid::Uuid,
    organization_id: Option<uuid::Uuid>,
    application_id: Option<uuid::Uuid>,
    hours: Option<f64>,
    instance_type: Option<String>,
}

/// Simulate resource usage for testing the billing pipeline
#[tracing::instrument(skip_all, err)]
async fn test_simulate_usage(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulateUsageRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TestSimulateUsageError> {
    use TestSimulateUsageErrorCtx as Ctx;

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

    let Some(pricing) = state.calculator.calculate_pricing(&usage) else {
        return Err(TestSimulateUsageError::NoPricing {
            resource_type: usage.resource_type.as_str().to_string(),
            location: std::panic::Location::caller(),
        });
    };
    let cost = pricing.total_cost_usd(usage.quantity);

    sqlx::query(
        r#"
        INSERT INTO usage_ledger (
            organization_id, user_id, application_id, resource_id, provider, resource_type,
            quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(usage.organization_id)
    .bind(usage.user_id)
    .bind(req.application_id)
    .bind(&usage.resource_id)
    .bind(usage.provider.as_str())
    .bind(usage.resource_type.as_str())
    .bind(usage.quantity)
    .bind(usage.unit.as_str())
    .bind(pricing.base_unit_cost_usd)
    .bind(pricing.margin_percent)
    .bind(now)
    .bind(&usage.metadata)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!(
        "TEST: Simulated {} hours of {} usage for user {}, cost: ${:.4}",
        hours,
        instance_type,
        req.user_id,
        cost
    );

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "resource_id": resource_id,
            "hours": hours,
            "instance_type": instance_type,
            "cost_usd": cost,
            "message": "Usage recorded locally. Paddle transaction will be created at billing cycle end."
        })),
    ))
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
    #[serde(default)]
    custom_data: Option<serde_json::Value>, // optional transaction custom_data (e.g. to exercise credit-purchase paths)
}

/// Simulate a Paddle transaction webhook for testing email and billing flow
#[tracing::instrument(skip_all, err)]
async fn test_simulate_paddle_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulatePaddleTransactionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TestSimulatePaddleTransactionError> {
    use TestSimulatePaddleTransactionErrorCtx as Ctx;

    let transaction_id = req
        .transaction_id
        .unwrap_or_else(|| format!("txn_test_{}", uuid::Uuid::new_v4()));
    let event_type = req
        .event_type
        .unwrap_or_else(|| "transaction.billed".to_string());
    let invoice_number = format!("TEST-{}", transaction_id[9..17].to_uppercase());

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
            },
            "custom_data": req.custom_data.clone().unwrap_or(serde_json::Value::Null)
        }),
    };

    tracing::info!(
        "TEST: Simulating Paddle {} for user {} (${:.2})",
        event_type,
        req.user_id,
        req.amount_cents as f64 / 100.0
    );

    webhooks::handle_paddle_transaction_test(&state, payload)
        .await
        .with_context(Ctx::webhook())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "transaction_id": transaction_id,
            "event_type": event_type,
            "invoice_number": invoice_number,
            "amount_cents": req.amount_cents,
            "message": "Paddle transaction processed. Check email service logs for notifications."
        })),
    ))
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
#[tracing::instrument(skip_all, err)]
async fn sync_aws_costs(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SyncAwsCostsRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), SyncAwsCostsError> {
    use SyncAwsCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = req.start_date.unwrap_or(default_start);
    let end_date = req.end_date.unwrap_or(default_end);

    tracing::info!("Syncing AWS costs from {} to {}", start_date, end_date);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    let mut synced_count = 0;
    let mut total_cost = 0.0;

    for (org_id, cost_data) in &org_costs {
        let parsed_org_id: uuid::Uuid = match org_id.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!("Skipping non-UUID org_id: {}", org_id);
                continue;
            }
        };

        let now = time::OffsetDateTime::now_utc();
        let result = sqlx::query(
            r#"
            INSERT INTO usage_ledger (
                organization_id, application_id, resource_id, provider, resource_type,
                quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
            )
            VALUES ($1, NULL, $2, 'aws', 'aws_cost_explorer', $3, 'usd', 1, 0, $4, $5)
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

    Ok((
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
    ))
}

#[derive(serde::Deserialize)]
struct GetAwsCostsQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

/// Get AWS costs for a specific org
#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
async fn get_aws_org_costs(
    Path(org_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetAwsOrgCostsError> {
    use GetAwsOrgCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let cost_data = ce_client
        .get_org_costs(&org_id, &start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    Ok((StatusCode::OK, Json(serde_json::json!(cost_data))))
}

/// Get AWS costs for all orgs (summary)
#[tracing::instrument(skip_all, err)]
async fn get_all_aws_costs(
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetAllAwsCostsError> {
    use GetAllAwsCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    let total: f64 = org_costs.values().map(|c| c.total_cost).sum();

    Ok((
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
    ))
}

#[cfg(test)]
mod tests {
    use super::{BILLING_URL, has_valid_internal_service_secret, load_internal_service_secret};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn billing_url_points_to_dashboard_billing_hash() {
        assert_eq!(BILLING_URL, "https://dashboard.caution.co/#billing");
    }

    #[test]
    fn load_internal_service_secret_accepts_non_empty_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "super-secret");
        }
        let secret = load_internal_service_secret().expect("secret should load");
        assert_eq!(secret, "super-secret");
        drop(guard);
    }

    #[test]
    fn load_internal_service_secret_rejects_missing_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::remove_var("INTERNAL_SERVICE_SECRET");
        }
        let err = load_internal_service_secret().expect_err("missing secret should fail");
        assert!(
            err.to_string()
                .contains("INTERNAL_SERVICE_SECRET must be set")
        );
        drop(guard);
    }

    #[test]
    fn load_internal_service_secret_rejects_empty_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "   ");
        }
        let err = load_internal_service_secret().expect_err("empty secret should fail");
        assert!(
            err.to_string()
                .contains("INTERNAL_SERVICE_SECRET must be set")
        );
        drop(guard);
    }

    #[test]
    fn has_valid_internal_service_secret_requires_exact_match() {
        assert!(has_valid_internal_service_secret("secret", Some("secret")));
        assert!(!has_valid_internal_service_secret("secret", Some("wrong")));
        assert!(!has_valid_internal_service_secret("secret", None));
    }
}

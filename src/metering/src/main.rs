// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BILLING_URL: &str = "https://dashboard.caution.co/#billing";

mod calculator;
mod cost_explorer;
mod credits;
mod paddle;
mod types;

mod auth_middleware;
mod balance;
mod handlers;
mod rate_limit;

pub struct AppState {
    pub pool: sqlx::PgPool,
    pub paddle: paddle::PaddleClient,
    pub calculator: calculator::CostCalculator,
    pub pricing: caution_config::pricing::PricingConfig,
    pub cloudwatch: aws_sdk_cloudwatch::Client,
    pub internal_service_secret: String,
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

    let internal_service_secret =
        auth_middleware::load_internal_service_secret().unwrap_or_else(|e| {
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
    let calculator =
        calculator::CostCalculator::new(calculator::PricingRules::load().unwrap_or_else(|e| {
            eprintln!("FATAL: Failed to load pricing rules: {e}");
            std::process::exit(1);
        }));

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
            let result = std::panic::AssertUnwindSafe(handlers::run_collection_loop(
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
            let result = std::panic::AssertUnwindSafe(handlers::run_monthly_billing_loop(
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
                std::panic::AssertUnwindSafe(handlers::run_dunning_loop(dunning_state.clone()));
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
        .route("/api/resources/track", post(handlers::track_resource))
        .route(
            "/api/resources/{resource_id}/untrack",
            post(handlers::untrack_resource),
        )
        .route("/api/resources", get(handlers::list_tracked_resources))
        .route("/api/usage/{user_id}", get(handlers::get_user_usage))
        .route("/api/collect", post(handlers::trigger_collection))
        // AWS Cost Explorer endpoints
        .route("/api/aws/costs/sync", post(handlers::sync_aws_costs))
        .route("/api/aws/costs/{org_id}", get(handlers::get_aws_org_costs))
        .route("/api/aws/costs", get(handlers::get_all_aws_costs))
        // Monthly billing
        .route(
            "/api/billing/monthly",
            post(handlers::trigger_monthly_billing),
        )
        // User-facing billing dashboard
        .route(
            "/api/billing/estimate/{org_id}",
            get(handlers::get_billing_estimate),
        );

    // Test endpoints: only available when ENABLE_TEST_ENDPOINTS=true
    if enable_test_endpoints {
        tracing::warn!("Test endpoints enabled — do NOT use in production");
        api_routes = api_routes
            .route("/test/simulate-usage", post(handlers::test_simulate_usage))
            .route(
                "/test/simulate-paddle-transaction",
                post(handlers::test_simulate_paddle_transaction),
            );
    }

    let api_routes = api_routes.layer(middleware::from_fn_with_state(
        state.clone(),
        auth_middleware::internal_auth_middleware,
    ));

    // Webhook rate limiter: 30 requests per minute per IP
    let webhook_limiter = rate_limit::RateLimiter::new(30, std::time::Duration::from_secs(60));

    // Public routes — no auth required (health check, webhooks have their own signature verification)
    let webhook_routes = Router::new()
        .route("/webhooks/paddle", post(handlers::paddle_webhook_handler))
        .layer(middleware::from_fn_with_state(
            webhook_limiter,
            rate_limit::webhook_rate_limit_middleware,
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

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("FATAL: Failed to bind listener on {addr}: {e}");
            std::process::exit(1);
        });
    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("FATAL: Server error: {e}");
        std::process::exit(1);
    });
}

#[tracing::instrument(skip_all)]
async fn health_check() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::BILLING_URL;

    #[test]
    fn billing_url_points_to_dashboard_billing_hash() {
        assert_eq!(BILLING_URL, "https://dashboard.caution.co/#billing");
    }
}

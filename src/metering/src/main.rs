// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod calculator;
mod cost_explorer;
mod lago;
mod providers;
mod types;
mod webhooks;

use types::*;

pub struct AppState {
    pub pool: sqlx::PgPool,
    pub lago: lago::LagoClient,
    pub calculator: calculator::CostCalculator,
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

    let lago_url = std::env::var("LAGO_URL")
        .unwrap_or_else(|_| "http://lago-api:3000".to_string());
    let lago_api_key = std::env::var("LAGO_API_KEY")
        .unwrap_or_else(|_| "".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    tracing::info!("Connected to database");

    let lago = lago::LagoClient::new(lago_url, lago_api_key);
    let calculator = calculator::CostCalculator::new(calculator::PricingRules::default());

    let state = Arc::new(AppState {
        pool,
        lago,
        calculator,
    });

    // Start background metering collection task
    let collection_state = state.clone();
    let collection_interval_secs: u64 = std::env::var("METERING_INTERVAL_SECS")
        .unwrap_or_else(|_| "300".to_string()) // 5 minutes default
        .parse()
        .unwrap_or(300);

    tokio::spawn(async move {
        run_collection_loop(collection_state, collection_interval_secs).await;
    });

    // Start monthly billing cycle (checks daily, runs at month-end)
    let billing_state = state.clone();
    tokio::spawn(async move {
        run_monthly_billing_loop(billing_state).await;
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/resources/track", post(track_resource))
        .route("/api/resources/{resource_id}/untrack", post(untrack_resource))
        .route("/api/resources", get(list_tracked_resources))
        .route("/api/usage/{user_id}", get(get_user_usage))
        .route("/api/collect", post(trigger_collection))
        .route("/webhooks/lago", post(webhooks::lago_webhook_handler))
        // Test endpoints for simulating billing flow
        .route("/test/simulate-usage", post(test_simulate_usage))
        .route("/test/simulate-invoice", post(test_simulate_invoice))
        // AWS Cost Explorer endpoints
        .route("/api/aws/costs/sync", post(sync_aws_costs))
        .route("/api/aws/costs/{org_id}", get(get_aws_org_costs))
        .route("/api/aws/costs", get(get_all_aws_costs))
        // Monthly billing
        .route("/api/billing/monthly", post(trigger_monthly_billing))
        // User-facing billing dashboard
        .route("/api/billing/estimate/{org_id}", get(get_billing_estimate))
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
            SUM(quantity) as total_quantity,
            SUM(cost_usd) as total_cost
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
    match run_collection_cycle(&state).await {
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

    // Track if we've already billed this month
    let mut last_billed_month: Option<time::Month> = None;

    loop {
        interval.tick().await;

        let now = time::OffsetDateTime::now_utc();
        let today = now.date();
        let current_month = today.month();

        // Check if it's the last day of the month (or first few days of next month as fallback)
        let is_last_day = is_last_day_of_month(today);
        let is_first_of_month = today.day() <= 3; // Fallback: run in first 3 days if we missed month-end

        // Only bill once per month
        let already_billed = last_billed_month == Some(current_month);

        if (is_last_day || (is_first_of_month && !already_billed)) && !already_billed {
            tracing::info!("Running monthly billing cycle for {}", current_month);

            if let Err(e) = run_monthly_billing_cycle(&state).await {
                tracing::error!("Monthly billing cycle failed: {}", e);
            } else {
                last_billed_month = Some(current_month);
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

        // Report to Lago to generate invoice
        let usage = ResourceUsage {
            user_id,
            resource_id: format!("monthly-{}", start_date),
            provider: Provider::Aws,
            resource_type: ResourceType::Custom("monthly_total".to_string()),
            quantity: cost_data.total_cost,
            unit: UsageUnit::Custom("usd".to_string()),
            timestamp: now,
            metadata: serde_json::json!({
                "billing_period": format!("{} to {}", start_date, end_date),
                "services": cost_data.costs_by_service,
            }),
        };

        if let Err(e) = state.lago.report_usage(&usage, cost_data.total_cost).await {
            tracing::warn!("Failed to report to Lago for org {}: {}", org_id, e);
        }
    }

    // Trigger Lago to finalize invoices
    // (Lago typically does this automatically based on billing cycle config)
    tracing::info!("Monthly billing cycle complete - Lago will generate invoices");

    Ok(())
}

async fn run_collection_cycle(state: &AppState) -> Result<usize> {
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

    for resource in resources {
        if let Err(e) = collect_resource_usage(state, &resource.resource_id).await {
            tracing::error!("Failed to collect usage for {}: {}", resource.resource_id, e);
        } else {
            collected += 1;
        }
    }

    tracing::info!("Collected usage for {} resources", collected);
    Ok(collected)
}

async fn collect_resource_usage(state: &AppState, resource_id: &str) -> Result<()> {
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
        return Ok(());
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

    // Report to Lago
    if let Err(e) = state.lago.report_usage(&usage, cost).await {
        tracing::warn!("Failed to report to Lago (will retry): {}", e);
    }

    Ok(())
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

            // Report to Lago if configured
            if let Err(e) = state.lago.report_usage(&usage, cost).await {
                tracing::warn!("Failed to report to Lago: {}", e);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "resource_id": resource_id,
                "hours": hours,
                "instance_type": instance_type,
                "cost_usd": cost,
                "message": "Usage recorded. If Lago is configured, it will generate an invoice."
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
struct TestSimulateInvoiceRequest {
    user_id: uuid::Uuid,
    amount_cents: i64,
    #[serde(default)]
    payment_status: Option<String>,  // pending, succeeded, failed
}

/// Simulate a Lago invoice webhook for testing email and payment flow
async fn test_simulate_invoice(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSimulateInvoiceRequest>,
) -> impl IntoResponse {
    let invoice_id = uuid::Uuid::new_v4().to_string();
    let invoice_number = format!("TEST-{}", &invoice_id[..8].to_uppercase());
    let payment_status = req.payment_status.unwrap_or_else(|| "pending".to_string());

    // Build a fake Lago webhook payload
    let webhook_payload = serde_json::json!({
        "webhook_type": "invoice_created",
        "invoice": {
            "lago_id": invoice_id,
            "sequential_id": 1,
            "number": invoice_number,
            "issuing_date": time::OffsetDateTime::now_utc().date().to_string(),
            "status": "finalized",
            "payment_status": payment_status,
            "currency": "USD",
            "total_amount_cents": req.amount_cents,
            "taxes_amount_cents": 0,
            "sub_total_excluding_taxes_amount_cents": req.amount_cents,
            "customer": {
                "lago_id": uuid::Uuid::new_v4().to_string(),
                "external_id": req.user_id.to_string(),
                "email": null,
                "name": null,
            },
            "fees": [],
            "file_url": null,
        }
    });

    tracing::info!(
        "TEST: Simulating invoice {} for user {} (${:.2})",
        invoice_number,
        req.user_id,
        req.amount_cents as f64 / 100.0
    );

    // Process it through the webhook handler
    let event: webhooks::LagoWebhookEvent = match serde_json::from_value(webhook_payload.clone()) {
        Ok(e) => e,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to parse test webhook: {}", e)
            })));
        }
    };

    // Handle the event
    match event {
        webhooks::LagoWebhookEvent::InvoiceCreated { invoice } => {
            // This will record the invoice and try to process payment
            let result = webhooks::handle_invoice_created_test(&state, invoice).await;
            match result {
                Ok(_) => (StatusCode::OK, Json(serde_json::json!({
                    "status": "success",
                    "invoice_number": invoice_number,
                    "amount_cents": req.amount_cents,
                    "message": "Invoice processed. Check email service logs for notifications."
                }))),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": e.to_string()
                }))),
            }
        }
        _ => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Unexpected event type"
        }))),
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

                // Report to Lago if configured
                let usage = ResourceUsage {
                    user_id,
                    resource_id: format!("aws-costs-{}", start_date),
                    provider: Provider::Aws,
                    resource_type: ResourceType::Custom("aws_total".to_string()),
                    quantity: cost_data.total_cost,
                    unit: UsageUnit::Custom("usd".to_string()),
                    timestamp: now,
                    metadata: serde_json::json!({
                        "source": "cost_explorer",
                        "period": format!("{} to {}", start_date, end_date),
                    }),
                };

                if let Err(e) = state.lago.report_usage(&usage, cost_data.total_cost).await {
                    tracing::warn!("Failed to report to Lago for org {}: {}", org_id, e);
                }
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

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Extension, Path, State, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put, patch, delete},
    Json, Router,
};
use tokio_stream::wrappers::ReceiverStream;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, FromRow, Row};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use base64::Engine;
use subtle::ConstantTimeEq;
use chrono::{DateTime, Datelike, Utc};
use uuid::Uuid;
use enclave_builder::{BuildConfig as DockerBuildConfig, build_user_image};

mod provisioning;
mod deployment;
mod ec2;
mod validation;
mod validated_types;
mod onboarding;
mod types;
mod errors;
mod encryption;
mod cloud_credentials;
mod cryptographic_bundles;
mod gpg;

#[derive(Clone, Debug, Deserialize)]
struct PricingConfig {
    #[serde(default)]
    compute_margin_percent: f64,
    #[serde(default)]
    subscription_tiers: std::collections::HashMap<String, TierPricing>,
    #[serde(default)]
    extra_block_annual_cents: i64,
    #[serde(default)]
    billing_discounts: BillingDiscounts,
    #[serde(default)]
    credit_packages: std::collections::HashMap<String, CreditPackagePricing>,
}

#[derive(Clone, Debug, Deserialize)]
struct TierPricing {
    annual_cents: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct BillingDiscounts {
    #[serde(default)]
    yearly_percent_off: f64,
    #[serde(default)]
    two_year_percent_off: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct CreditPackagePricing {
    bonus_percent: f64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            compute_margin_percent: 0.0,
            subscription_tiers: std::collections::HashMap::new(),
            extra_block_annual_cents: 0,
            billing_discounts: BillingDiscounts::default(),
            credit_packages: std::collections::HashMap::new(),
        }
    }
}

impl PricingConfig {
    fn load() -> Self {
        match std::fs::read_to_string("prices.json") {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded pricing config from prices.json");
                    config
                }
                Err(e) => {
                    tracing::error!("Failed to parse prices.json: {}. Using defaults (all zeros).", e);
                    Self::default()
                }
            },
            Err(_) => {
                tracing::warn!("prices.json not found. Using defaults (all zeros). Copy prices.json.example to prices.json to configure pricing.");
                Self::default()
            }
        }
    }

    fn tier_annual_cents(&self, tier_id: &str) -> i64 {
        self.subscription_tiers.get(tier_id).map(|t| t.annual_cents).unwrap_or(0)
    }

    fn credit_bonus_percent(&self, package_key: &str) -> f64 {
        self.credit_packages.get(package_key).map(|p| p.bonus_percent).unwrap_or(0.0)
    }
}

#[derive(Clone)]
struct AppState {
    db: PgPool,
    git_hostname: String,
    git_ssh_port: Option<u16>,
    data_dir: String,
    encryptor: Option<Arc<encryption::Encryptor>>,
    internal_service_secret: Option<String>,
    paddle_client_token: Option<String>,
    paddle_setup_price_id: Option<String>,
    paddle_credits_price_ids: [Option<String>; 3],
    paddle_api_url: String,
    paddle_api_key: Option<String>,
    pricing: PricingConfig,
}

#[derive(Clone)]
struct AuthContext {
    user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct User {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::UpdateUserRequest;

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct Organization {
    id: Uuid,
    name: String,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::{CreateOrganizationRequest, UpdateOrganizationRequest};

#[derive(Debug, Serialize, FromRow)]
struct OrganizationMember {
    id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    role: String,
    joined_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::{AddMemberRequest, UpdateMemberRequest, UpdateOrgSettingsRequest};

#[derive(Debug, Serialize, Deserialize)]
struct OrgSettings {
    require_pin: bool,
}

#[derive(Debug, Serialize, FromRow)]
struct ComputeResource {
    id: Uuid,
    organization_id: Uuid,
    provider_account_id: Uuid,
    resource_type_id: Uuid,
    provider_resource_id: String,
    resource_name: Option<String>,
    state: String,
    region: Option<String>,
    public_ip: Option<String>,
    domain: Option<String>,
    billing_tag: Option<String>,
    configuration: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::{CreateResourceRequest, CreateResourceResponse, RenameResourceRequest};
use validated_types::{DeployRequest, DeployResponse};

#[derive(Debug, Serialize, Clone)]
struct CreditPackage {
    purchase_cents: i64,
    credit_cents: i64,
    bonus_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    paddle_price_id: Option<String>,
}

// Credit package base amounts (purchase_cents). Bonus percentages come from prices.json.
const CREDIT_PACKAGE_BASES: &[(i64, &str)] = &[
    (100_000,   "1000"),
    (500_000,   "5000"),
    (2_500_000, "25000"),
];

fn build_credit_packages(pricing: &PricingConfig, paddle_ids: &[Option<String>; 3]) -> Vec<CreditPackage> {
    CREDIT_PACKAGE_BASES.iter().enumerate().map(|(i, &(purchase_cents, key))| {
        let bonus_percent = pricing.credit_bonus_percent(key);
        let credit_cents = purchase_cents + (purchase_cents as f64 * bonus_percent / 100.0) as i64;
        CreditPackage {
            purchase_cents,
            credit_cents,
            bonus_percent,
            paddle_price_id: paddle_ids[i].clone(),
        }
    }).collect()
}

// --- Managed On-Prem Subscription Tiers ---

#[derive(Debug, Clone, Serialize)]
struct SubscriptionTier {
    id: &'static str,
    name: &'static str,
    max_vcpus: i32,
    max_apps: i32, // -1 = unlimited
}

const SUBSCRIPTION_TIERS: &[SubscriptionTier] = &[
    SubscriptionTier { id: "starter",       name: "Starter",         max_vcpus: 16,  max_apps: 2  },
    SubscriptionTier { id: "developer",     name: "Developer",       max_vcpus: 64,  max_apps: 5  },
    SubscriptionTier { id: "base_platform", name: "Base Platform",   max_vcpus: 64,  max_apps: 10 },
    SubscriptionTier { id: "growth",        name: "Growth Band",     max_vcpus: 256, max_apps: 25 },
    SubscriptionTier { id: "enterprise",    name: "Enterprise Band", max_vcpus: 512, max_apps: 50 },
];

fn calculate_cycle_price(annual_cents: i64, billing_period: &str, discounts: &BillingDiscounts) -> i64 {
    match billing_period {
        "yearly" => (annual_cents as f64 * (1.0 - discounts.yearly_percent_off / 100.0)) as i64,
        "2year"  => (annual_cents as f64 * 2.0 * (1.0 - discounts.two_year_percent_off / 100.0)) as i64,
        _        => annual_cents / 12,
    }
}

fn calculate_period_end(start: DateTime<Utc>, billing_period: &str) -> DateTime<Utc> {
    match billing_period {
        "yearly" => start + chrono::Duration::days(365),
        "2year"  => start + chrono::Duration::days(730),
        _        => {
            // Monthly: advance by 1 calendar month
            let (y, m) = if start.month() == 12 {
                (start.year() + 1, 1)
            } else {
                (start.year(), start.month() + 1)
            };
            let day = start.day().min(days_in_month(y, m));
            start.with_year(y).unwrap()
                 .with_month(m).unwrap()
                 .with_day(day).unwrap()
        }
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    use chrono::NaiveDate;
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    NaiveDate::from_ymd_opt(ny, nm, 1).unwrap()
        .signed_duration_since(NaiveDate::from_ymd_opt(year, month, 1).unwrap())
        .num_days() as u32
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Check which auth method is being used
    let internal_secret = headers.get("x-internal-service-secret").and_then(|h| h.to_str().ok());
    let session_id = headers.get("x-session-id").and_then(|h| h.to_str().ok());

    // Internal service authentication (takes precedence if secret header is present)
    if let Some(provided_secret) = internal_secret {
        let Some(ref configured_secret) = state.internal_service_secret else {
            tracing::warn!("Auth middleware: internal service auth rejected - no secret configured on server");
            return Err((StatusCode::UNAUTHORIZED, "Internal service authentication not configured".to_string()));
        };

        if !bool::from(provided_secret.as_bytes().ct_eq(configured_secret.as_bytes())) {
            tracing::warn!("Auth middleware: internal service auth rejected - invalid secret");
            return Err((StatusCode::UNAUTHORIZED, "Invalid internal service secret".to_string()));
        }

        let Some(user_id_str) = headers.get("x-authenticated-user-id").and_then(|h| h.to_str().ok()) else {
            tracing::warn!("Auth middleware: internal service auth rejected - missing user ID");
            return Err((StatusCode::UNAUTHORIZED, "Missing user ID for internal service auth".to_string()));
        };

        let Ok(user_id) = Uuid::parse_str(user_id_str) else {
            tracing::warn!("Auth middleware: internal service auth rejected - invalid user ID format");
            return Err((StatusCode::UNAUTHORIZED, "Invalid user ID format".to_string()));
        };

        tracing::debug!("Auth middleware: internal service auth for user_id={}", user_id);
        request.extensions_mut().insert(AuthContext { user_id });
        return Ok(next.run(request).await);
    }

    // Session-based authentication
    if let Some(session_id) = session_id {
        tracing::debug!("Auth middleware: validating session");
        let user_id = validate_session(&state.db, session_id).await.map_err(|status| {
            let msg = match status {
                StatusCode::UNAUTHORIZED => "Invalid or expired session".to_string(),
                _ => "Authentication failed".to_string(),
            };
            (status, msg)
        })?;
        tracing::debug!("Session validated: user_id={}", user_id);
        request.extensions_mut().insert(AuthContext { user_id });
        return Ok(next.run(request).await);
    }

    // No valid authentication method provided
    tracing::debug!("Auth middleware: no authentication provided");
    Err((StatusCode::UNAUTHORIZED, "No authentication provided".to_string()))
}

/// Internal-only auth middleware — rejects session-based auth, requires service secret + user_id.
async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let internal_secret = headers.get("x-internal-service-secret").and_then(|h| h.to_str().ok());

    let Some(provided_secret) = internal_secret else {
        return Err((StatusCode::UNAUTHORIZED, "Internal service secret required".to_string()));
    };

    let Some(ref configured_secret) = state.internal_service_secret else {
        return Err((StatusCode::UNAUTHORIZED, "Internal service authentication not configured".to_string()));
    };

    if !bool::from(provided_secret.as_bytes().ct_eq(configured_secret.as_bytes())) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid internal service secret".to_string()));
    }

    // User ID is optional for internal routes — most operate on org_id from path
    if let Some(user_id_str) = headers.get("x-authenticated-user-id").and_then(|h| h.to_str().ok()) {
        if let Ok(user_id) = Uuid::parse_str(user_id_str) {
            request.extensions_mut().insert(AuthContext { user_id });
        }
    }

    Ok(next.run(request).await)
}

async fn onboarding_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    ensure_user_has_org(&state.db, auth.user_id).await?;

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

async fn validate_session(db: &PgPool, session_id: &str) -> Result<Uuid, StatusCode> {
    let result: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id
         FROM auth_sessions s
         INNER JOIN fido2_credentials c ON s.credential_id = c.credential_id
         INNER JOIN users u ON c.user_id = u.id
         WHERE s.session_id = $1 AND s.expires_at > NOW()"
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Session validation query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    result.map(|(user_id,)| user_id).ok_or_else(|| {
        tracing::warn!("Invalid or expired session");
        StatusCode::UNAUTHORIZED
    })
}

async fn ensure_user_has_org(db: &PgPool, user_id: Uuid) -> Result<(), StatusCode> {
    tracing::debug!("ensure_user_has_org: checking user {}", user_id);

    let is_onboarded = onboarding::check_onboarding_status(db, user_id).await?;

    if !is_onboarded {
        tracing::warn!("User {} has not completed onboarding", user_id);
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let has_org: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check user org membership: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if has_org.is_some() {
        tracing::debug!("User {} already has organization", user_id);
        return Ok(());
    }

    tracing::info!("User {} has no organization, initializing new account", user_id);

    provisioning::initialize_user_account(db, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize user account: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Successfully initialized account for user {}", user_id);
    Ok(())
}

async fn check_org_access(
    db: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<types::UserRole, StatusCode> {
    let member: Option<(types::UserRole,)> = sqlx::query_as(
        "SELECT role FROM organization_members
         WHERE organization_id = $1 AND user_id = $2"
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("check_org_access failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    member.map(|m| m.0).ok_or(StatusCode::FORBIDDEN)
}

fn can_manage_org(role: &types::UserRole) -> bool {
    role.can_manage_org()
}

fn is_owner(role: &types::UserRole) -> bool {
    role.is_owner()
}

async fn get_user_primary_org(db: &PgPool, user_id: Uuid) -> Result<Uuid, StatusCode> {
    let org_id: Option<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members
         WHERE user_id = $1
         ORDER BY created_at ASC
         LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    org_id.map(|o| o.0).ok_or(StatusCode::NOT_FOUND)
}

async fn get_or_create_provider_account(
    db: &PgPool,
    org_id: Uuid,
) -> Result<Uuid, StatusCode> {
    let aws_account_id = std::env::var("AWS_ACCOUNT_ID")
        .map_err(|_| {
            tracing::error!("AWS_ACCOUNT_ID environment variable not set");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let existing: Option<(Uuid, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT pa.id, pa.role_arn, pa.is_active FROM provider_accounts pa
         JOIN providers p ON pa.provider_id = p.id
         WHERE pa.organization_id = $1 AND p.provider_type = 'aws'
         LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((id, role_arn, is_active)) = existing {
        if role_arn.is_none() || is_active != Some(true) {
            let role_arn = format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", aws_account_id);

            sqlx::query(
                "UPDATE provider_accounts
                 SET role_arn = $1, is_active = true, external_account_id = $2
                 WHERE id = $3 AND organization_id = $4"
            )
            .bind(&role_arn)
            .bind(&aws_account_id)
            .bind(id)
            .bind(org_id)
            .execute(db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update provider account: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            tracing::info!("Updated provider account {} for org {}", id, org_id);
        }
        return Ok(id);
    }

    let role_arn = format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", aws_account_id);

    let account_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO provider_accounts
         (organization_id, provider_id, external_account_id, account_name, role_arn, is_active)
         VALUES ($1, (SELECT id FROM providers WHERE provider_type = 'aws'), $2, $3, $4, true)
         RETURNING id"
    )
    .bind(org_id)
    .bind(&aws_account_id)
    .bind(format!("AWS Account {}", aws_account_id))
    .bind(&role_arn)
    .fetch_one(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create provider account: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Created provider account {} for org {} using AWS account {}", account_id.0, org_id, aws_account_id);

    Ok(account_id.0)
}

async fn get_or_create_resource_type(db: &PgPool) -> Result<Uuid, StatusCode> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT rt.id FROM resource_types rt
         JOIN providers p ON rt.provider_id = p.id
         WHERE p.provider_type = 'aws' AND rt.type_code = $1
         LIMIT 1"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((id,)) = existing {
        return Ok(id);
    }

    let type_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO resource_types
         (provider_id, type_code, display_name, category)
         VALUES ((SELECT id FROM providers WHERE provider_type = 'aws'), $1, 'EC2 Instance', 'compute')
         RETURNING id"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_one(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(type_id.0)
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn wait_for_attestation_health(public_ip: &str, timeout_secs: u64) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!("http://{}/attestation", public_ip);
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        tracing::info!("Polling attestation endpoint (attempt {}): {}", attempt, url);

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let result = client
            .post(&url)
            .json(&serde_json::json!({"nonce": nonce_b64}))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Attestation endpoint is healthy after {} attempts", attempt);
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!("Attestation endpoint returned {}, retrying...", resp.status());
            }
            Err(e) => {
                tracing::debug!("Attestation endpoint not ready: {}", e);
            }
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "Attestation endpoint did not become healthy within {} seconds",
                timeout_secs
            ));
        }

        let delay = std::cmp::min(2u64.pow(attempt.min(4)), 30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }
}

async fn get_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<User>, StatusCode> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, is_active, created_at, updated_at 
         FROM users WHERE id = $1"
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}

async fn update_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<UpdateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    if payload.username.is_none() && payload.email.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE users SET ");
    let mut has_updates = false;

    if let Some(username) = &payload.username {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("username = ");
        query_builder.push_bind(username);
        has_updates = true;
    }

    if let Some(email) = &payload.email {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("email = ");
        query_builder.push_bind(email);
        has_updates = true;
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(auth.user_id);
    query_builder.push(" RETURNING id, username, email, is_active, created_at, updated_at");

    let user = query_builder
        .build_query_as::<User>()
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(user))
}

async fn delete_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<Organization>>, StatusCode> {
    tracing::debug!("list_organizations called for user {}", auth.user_id);
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT o.id, o.name, o.is_active, o.created_at, o.updated_at
         FROM organizations o
         INNER JOIN organization_members om ON o.id = om.organization_id
         WHERE om.user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("list_organizations failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("list_organizations returning {} orgs", orgs.len());
    Ok(Json(orgs))
}

async fn create_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateOrganizationRequest>,
) -> Result<Json<Organization>, StatusCode> {
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (name)
         VALUES ($1)
         RETURNING id, name, is_active, created_at, updated_at"
    )
    .bind(&payload.name)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)"
    )
    .bind(org.id)
    .bind(auth.user_id)
    .bind(types::UserRole::Owner)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(org))
}

async fn get_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Organization>, StatusCode> {
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, name, is_active, created_at, updated_at
         FROM organizations WHERE id = $1"
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(org))
}

async fn update_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrganizationRequest>,
) -> Result<Json<Organization>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    if payload.name.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE organizations SET ");

    if let Some(name) = &payload.name {
        query_builder.push("name = ");
        query_builder.push_bind(name);
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(org_id);
    query_builder.push(" RETURNING id, name, is_active, created_at, updated_at");

    let org = query_builder
        .build_query_as::<Organization>()
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(org))
}

async fn delete_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;
    
    if !is_owner(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE organizations SET is_active = false WHERE id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

#[tracing::instrument(skip(state, auth))]
async fn get_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgSettings>, StatusCode> {
    tracing::debug!("get_org_settings called for org {}", org_id);
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let settings: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT settings FROM organizations WHERE id = $1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("get_org_settings failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .flatten();

    let org_settings = settings
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or(OrgSettings { require_pin: false });

    tracing::debug!("get_org_settings returning: {:?}", org_settings);
    Ok(Json(org_settings))
}

#[tracing::instrument(skip(state, auth, payload))]
async fn update_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrgSettingsRequest>,
) -> Result<Json<OrgSettings>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Build the settings JSON update
    let mut settings = serde_json::json!({});
    if let Some(require_pin) = payload.require_pin {
        settings["require_pin"] = serde_json::json!(require_pin);
    }

    let updated_settings: serde_json::Value = sqlx::query_scalar(
        "UPDATE organizations
         SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb,
             updated_at = NOW()
         WHERE id = $2
         RETURNING settings"
    )
    .bind(&settings)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update org settings: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let org_settings: OrgSettings = serde_json::from_value(updated_settings.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse updated org settings: {:?}, raw value: {:?}", e, updated_settings);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(org_settings))
}

async fn list_members(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, StatusCode> {
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let members = sqlx::query_as::<_, OrganizationMember>(
        "SELECT id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at 
         FROM organization_members 
         WHERE organization_id = $1"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(members))
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<AddMemberRequest>,
) -> Result<Json<OrganizationMember>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;
    
    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    let member = sqlx::query_as::<_, OrganizationMember>(
        "INSERT INTO organization_members (organization_id, user_id, role, invited_by) 
         VALUES ($1, $2, $3::user_role, $4) 
         RETURNING id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at"
    )
    .bind(org_id)
    .bind(payload.user_id)
    .bind(&payload.role)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(member))
}

async fn update_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
    validated_types::Validated(payload): validated_types::Validated<UpdateMemberRequest>,
) -> Result<Json<OrganizationMember>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;
    
    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    let member = sqlx::query_as::<_, OrganizationMember>(
        "UPDATE organization_members 
         SET role = $1::user_role 
         WHERE organization_id = $2 AND user_id = $3 
         RETURNING id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at"
    )
    .bind(&payload.role)
    .bind(org_id)
    .bind(member_user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(member))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;
    
    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query(
        "DELETE FROM organization_members 
         WHERE organization_id = $1 AND user_id = $2"
    )
    .bind(org_id)
    .bind(member_user_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_commit_sha(app_name: &str, branch: &str, data_dir: &str) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let ref_spec = format!("refs/heads/{}", branch);

    let output = Command::new("git")
        .args(&["--git-dir", &repo_path, "rev-parse", &ref_spec])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to get commit SHA for branch '{}': {}", branch, stderr).into());
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(commit_sha)
}

async fn build_image_from_repo(
    app_name: &str,
    build_config: &types::BuildConfig,
    image_name: &str,
    branch: &str,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let work_dir = format!("{}/build/{}-build", data_dir, app_name);

    tracing::info!("Cloning repository from {} to {} (branch: {})", repo_path, work_dir, branch);

    fs::create_dir_all(format!("{}/build", data_dir)).await?;

    let _ = fs::remove_dir_all(&work_dir).await;

    let _ = Command::new("git")
        .args(&["config", "--global", "--add", "safe.directory", &repo_path])
        .output()
        .await;

    let output = Command::new("git")
        .args(&["clone", "--branch", branch, &repo_path, &work_dir])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git clone failed: {}", stderr).into());
    }

    tracing::info!("Successfully cloned repository (branch: {})", branch);

    let commit_output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .current_dir(&work_dir)
        .output()
        .await?;

    let commit_sha = if commit_output.status.success() {
        String::from_utf8_lossy(&commit_output.stdout).trim().to_string()
    } else {
        "unknown".to_string()
    };

    tracing::info!("Building commit: {}", commit_sha);

    // Use shared build logic from enclave-builder
    let docker_config = DockerBuildConfig {
        build_command: build_config.build.clone(),
        containerfile: build_config.containerfile.clone(),
        oci_tarball: build_config.oci_tarball.clone(),
        no_cache: build_config.no_cache,
    };

    let work_dir_path = std::path::PathBuf::from(&work_dir);

    // Build the Docker image (now async)
    build_user_image(&work_dir_path, image_name, &docker_config)
        .await
        .map_err(|e| format!("Build failed: {}", e))?;

    tracing::info!("Image built and tagged as {}", image_name);

    Ok(commit_sha)
}

async fn export_image_to_tarball(
    image_name: &str,
    tarball_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::process::Command;
    use tokio::fs;

    tracing::info!("Exporting image {} to {}", image_name, tarball_path);

    if let Some(parent) = std::path::Path::new(tarball_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    let output = Command::new("docker")
        .args(&["save", "-o", tarball_path, image_name])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Docker save failed: {}", stderr).into());
    }

    Ok(())
}

async fn create_ami_from_image(
    resource_id: &str,
    image_tarball: &str,
    aws_region: &str,
    _role_arn: Option<&str>,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::process::Command;

    let packer_dir = format!("{}/build/{}-packer", data_dir, resource_id);
    let _ = fs::remove_dir_all(&packer_dir).await;
    fs::create_dir_all(&packer_dir).await?;

    let packer_template = format!(
        r#"{{
  "variables": {{
    "aws_region": "{}",
    "resource_id": "{}",
    "image_tarball": "{}"
  }},
  "builders": [
    {{
      "type": "amazon-ebs",
      "region": "{{{{ user `aws_region` }}}}",
      "source_ami_filter": {{
        "filters": {{
          "name": "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
          "root-device-type": "ebs",
          "virtualization-type": "hvm"
        }},
        "owners": ["099720109477"],
        "most_recent": true
      }},
      "instance_type": "t3.small",
      "ssh_username": "ubuntu",
      "ami_name": "caution-{{{{ user `resource_id` }}}}-{{{{timestamp}}}}",
      "ami_description": "Caution resource: {{{{ user `resource_id` }}}}",
      "tags": {{
        "Name": "caution-{{{{ user `resource_id` }}}}",
        "ManagedBy": "Caution",
        "ResourceId": "{{{{ user `resource_id` }}}}"
      }}
    }}
  ],
  "provisioners": [
    {{
      "type": "shell",
      "inline": [
        "sleep 5",
        "sudo rm -rf /var/lib/apt/lists/*",
        "sudo apt-get clean",
        "sudo apt-get update -y || (sleep 5 && sudo apt-get update -y)",
        "sudo apt-get install -y containerd",
        "sudo systemctl enable containerd",
        "sudo systemctl start containerd"
      ]
    }},
    {{
      "type": "file",
      "source": "{{{{ user `image_tarball` }}}}",
      "destination": "/tmp/app.tar"
    }},
    {{
      "type": "shell",
      "inline": [
        "sudo ctr -n default images import /tmp/app.tar",
        "sudo ctr -n default images list",
        "sudo rm /tmp/app.tar"
      ]
    }},
    {{
      "type": "shell",
      "inline": [
        "cat <<'EOF' | sudo tee /etc/systemd/system/caution-app.service",
        "[Unit]",
        "Description=Caution Application Container",
        "After=containerd.service",
        "Requires=containerd.service",
        "",
        "[Service]",
        "Type=simple",
        "ExecStartPre=/usr/bin/ctr -n default images list",
        "ExecStart=/bin/sh -c '/usr/bin/ctr -n default run --rm --net-host $(/usr/bin/ctr -n default images list -q | head -1) caution-app'",
        "Restart=always",
        "RestartSec=10",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "EOF",
        "sudo systemctl enable caution-app.service"
      ]
    }}
  ]
}}"#,
        aws_region, resource_id, image_tarball
    );

    let template_path = format!("{}/template.json", packer_dir);
    fs::write(&template_path, packer_template.clone()).await?;

    tracing::info!("Running Packer to create AMI for {}", resource_id);
    tracing::debug!("Packer template:\n{}", packer_template);
    tracing::debug!("Packer template path: {}", template_path);
    tracing::debug!("Packer working directory: {}", packer_dir);

    match Command::new("packer").arg("version").output().await {
        Ok(version_output) => {
            let version = String::from_utf8_lossy(&version_output.stdout);
            tracing::info!("Packer version: {}", version.trim());
        }
        Err(e) => {
            tracing::warn!("Failed to get Packer version: {}", e);
        }
    }

    match Command::new("packer").args(&["plugins", "installed"]).output().await {
        Ok(plugins_output) => {
            let plugins_stdout = String::from_utf8_lossy(&plugins_output.stdout);
            let plugins_stderr = String::from_utf8_lossy(&plugins_output.stderr);
            tracing::info!("Packer plugins installed:\nstdout: {}\nstderr: {}", plugins_stdout.trim(), plugins_stderr.trim());
        }
        Err(e) => {
            tracing::warn!("Failed to list Packer plugins: {}", e);
        }
    }

    tracing::info!("Installing Packer Amazon plugin");
    match Command::new("packer")
        .args(&["plugins", "install", "github.com/hashicorp/amazon"])
        .output()
        .await
    {
        Ok(install_output) => {
            let install_stdout = String::from_utf8_lossy(&install_output.stdout);
            let install_stderr = String::from_utf8_lossy(&install_output.stderr);
            tracing::info!("Packer plugin install output:\nstdout: {}\nstderr: {}", install_stdout.trim(), install_stderr.trim());
            if !install_output.status.success() && !install_stderr.contains("already installed") {
                tracing::warn!("Plugin installation returned non-zero exit, but continuing: {}", install_stderr);
            }
        }
        Err(e) => {
            tracing::warn!("Failed to install packer plugin (may already be installed): {}", e);
        }
    }

    let mut cmd = Command::new("packer");
    cmd.args(&["build", "-force", &template_path])
        .env("AWS_REGION", aws_region)
        .current_dir(&packer_dir);

    let has_access_key = std::env::var("AWS_ACCESS_KEY_ID").is_ok();
    let has_secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").is_ok();

    tracing::info!("AWS credentials available: access_key={}, secret_key={}", has_access_key, has_secret_key);

    if let Ok(access_key) = std::env::var("AWS_ACCESS_KEY_ID") {
        cmd.env("AWS_ACCESS_KEY_ID", access_key);
        tracing::debug!("Set AWS_ACCESS_KEY_ID environment variable");
    }
    if let Ok(secret_key) = std::env::var("AWS_SECRET_ACCESS_KEY") {
        cmd.env("AWS_SECRET_ACCESS_KEY", secret_key);
        tracing::debug!("Set AWS_SECRET_ACCESS_KEY environment variable");
    }

    tracing::info!("Executing packer command: packer build -force {}", template_path);

    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let stdout_task = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut all_output = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            tracing::info!("Packer stdout: {}", line);
            all_output.push_str(&line);
            all_output.push('\n');
        }
        all_output
    });

    let stderr_task = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        let mut all_output = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!("Packer stderr: {}", line);
            all_output.push_str(&line);
            all_output.push('\n');
        }
        all_output
    });

    let status = child.wait().await?;
    let stdout_output = stdout_task.await.unwrap_or_default();
    let stderr_output = stderr_task.await.unwrap_or_default();

    if !status.success() {
        tracing::error!("Packer build failed with exit code: {:?}", status.code());
        tracing::error!("Full stdout:\n{}", stdout_output);
        tracing::error!("Full stderr:\n{}", stderr_output);
        return Err(format!("Packer build failed: {}", stderr_output).into());
    }

    tracing::info!("Packer build completed successfully");
    tracing::debug!("Packer full output: {}", stdout_output);

    fn strip_ansi_codes(s: &str) -> String {
        let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        re.replace_all(s, "").to_string()
    }

    let clean_output = strip_ansi_codes(&stdout_output);
    tracing::debug!("Clean Packer output (first 500 chars): {}", &clean_output.chars().take(500).collect::<String>());

    let ami_id = clean_output
        .lines()
        .rev()
        .find(|line| {
            (line.contains("us-west-2:") || line.contains("AMI:")) && line.contains("ami-")
        })
        .and_then(|line| {
            tracing::debug!("Found AMI line: {}", line);
            line.split_whitespace()
                .find(|s| s.starts_with("ami-"))
        })
        .ok_or_else(|| {
            tracing::error!("Could not find created AMI ID in Packer output. Full output:\n{}", clean_output);
            "Could not find created AMI ID in Packer output"
        })?
        .to_string();

    tracing::info!("Created AMI: {}", ami_id);

    Ok(ami_id)
}

async fn create_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateResourceRequest>,
) -> Result<Json<CreateResourceResponse>, StatusCode> {
    tracing::info!("Creating resource for user_id: {}", auth.user_id);
    tracing::debug!("Resource payload: {:?}", payload);

    let org_id = match get_user_primary_org(&state.db, auth.user_id).await {
        Ok(id) => {
            tracing::debug!("Found primary org: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get primary org for user {}: {:?}", auth.user_id, e);
            return Err(e);
        }
    };

    let provider_account_id = match get_or_create_provider_account(&state.db, org_id).await {
        Ok(id) => {
            tracing::debug!("Provider account: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get/create provider account: {:?}", e);
            return Err(e);
        }
    };

    let resource_type_id = match get_or_create_resource_type(&state.db).await {
        Ok(id) => {
            tracing::debug!("Resource type: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get/create resource type: {:?}", e);
            return Err(e);
        }
    };

    let provider_resource_id = Uuid::new_v4().to_string();

    // Use provided name (typically from directory name) or generate one
    let resource_slug = if let Some(ref name) = payload.name {
        // Validate the app name
        if let Err(e) = validation::validate_app_name(name) {
            tracing::warn!("Invalid app name '{}': {}, falling back to auto-generated", name, e);
            format!("app-{}", &provider_resource_id[..8])
        } else {
            // Check if name is already taken in this organization
            let existing: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM compute_resources
                 WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL"
            )
            .bind(org_id)
            .bind(name)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to check for existing resource name: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if existing.is_some() {
                tracing::warn!("App name '{}' already exists, falling back to auto-generated", name);
                format!("app-{}", &provider_resource_id[..8])
            } else {
                name.clone()
            }
        }
    } else {
        format!("app-{}", &provider_resource_id[..8])
    };

    let configuration = serde_json::json!({
        "cmd": payload.cmd
    });

    tracing::debug!("Creating resource with slug: {}", resource_slug);

    let resource: (Uuid, types::ResourceState, DateTime<Utc>) = match sqlx::query_as(
        "INSERT INTO compute_resources
         (organization_id, provider_account_id, resource_type_id, provider_resource_id,
          resource_name, state, configuration, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, state, created_at"
    )
    .bind(org_id)
    .bind(provider_account_id)
    .bind(resource_type_id)
    .bind(&provider_resource_id)
    .bind(&resource_slug)
    .bind(types::ResourceState::Pending)
    .bind(&configuration)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Database error creating resource: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let (resource_id, resource_state, created_at) = resource;

    let git_url = match state.git_ssh_port {
        Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    tracing::info!("Resource created successfully: id={}, name={}", resource_id, resource_slug);

    Ok(Json(CreateResourceResponse {
        id: resource_id,
        resource_name: resource_slug,
        git_url,
        state: resource_state.as_str().to_string(),
        created_at,
    }))
}

async fn list_resources(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let org_id = get_user_primary_org(&state.db, auth.user_id).await?;

    tracing::info!("Listing resources for user {} in org {}", auth.user_id, org_id);

    let resources = sqlx::query_as::<_, ComputeResource>(
        "SELECT id, organization_id, provider_account_id, resource_type_id,
                provider_resource_id, resource_name, state::text as state,
                region, public_ip, configuration->>'domain' as domain,
                billing_tag, configuration, created_at, updated_at
         FROM compute_resources
         WHERE organization_id = $1 AND destroyed_at IS NULL"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list resources: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Found {} resources", resources.len());

    let resources_with_git_url: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|resource| {
            let git_url = match state.git_ssh_port {
                Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource.id),
                None => format!("git@{}:{}.git", state.git_hostname, resource.id),
            };
            let mut value = serde_json::to_value(&resource).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("git_url".to_string(), serde_json::json!(git_url));
            }
            value
        })
        .collect();

    Ok(Json(resources_with_git_url))
}

async fn get_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let resource = sqlx::query_as::<_, ComputeResource>(
        "SELECT cr.id, cr.organization_id, cr.provider_account_id, cr.resource_type_id,
                cr.provider_resource_id, cr.resource_name, cr.state::text as state,
                cr.region, cr.public_ip, cr.configuration->>'domain' as domain,
                cr.billing_tag, cr.configuration, cr.created_at, cr.updated_at
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let git_url = match state.git_ssh_port {
        Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    let mut response = serde_json::to_value(&resource).unwrap_or_default();
    if let Some(obj) = response.as_object_mut() {
        obj.insert("git_url".to_string(), serde_json::json!(git_url));
    }

    Ok(Json(response))
}

async fn proxy_attestation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Get the resource to verify ownership and get the public IP + domain
    let resource: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT cr.public_ip, cr.configuration->>'domain' as domain
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Resource not found".to_string()))?;

    let public_ip = resource.0.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Resource has no public IP".to_string())
    })?;

    // Create HTTP client that accepts self-signed certs (for IP fallback)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create HTTP client: {}", e)))?;

    // Always use HTTPS — domain gets Let's Encrypt, IP gets self-signed cert
    // (danger_accept_invalid_certs handles the self-signed case)
    let attestation_url = if let Some(ref domain) = resource.1 {
        format!("https://{}/attestation", domain)
    } else {
        format!("https://{}/attestation", public_ip)
    };
    tracing::info!("Proxying attestation request to {}", attestation_url);

    let response = client
        .post(&attestation_url)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Attestation proxy request failed: {:?}", e);
            (StatusCode::BAD_GATEWAY, format!("Failed to reach attestation endpoint: {}", e))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Attestation endpoint returned error: {} - {}", status, body);
        return Err((StatusCode::BAD_GATEWAY, format!("Attestation endpoint error: {}", status)));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Invalid JSON from attestation endpoint: {}", e)))?;

    Ok(Json(json))
}

async fn rename_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<RenameResourceRequest>,
) -> Result<Json<ComputeResource>, (StatusCode, String)> {
    tracing::info!(
        "rename_resource: resource_id={}, user_id={}, new_name={}",
        resource_id, auth.user_id, payload.name
    );

    // Verify user has access to this resource via organization membership
    let resource: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT cr.organization_id, cr.resource_name
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error in rename_resource: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
    })?;

    let Some((org_id, old_name)) = resource else {
        return Err((StatusCode::NOT_FOUND, "Resource not found".to_string()));
    };

    // Check if the new name is already taken within this organization (for active resources)
    let name_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM compute_resources
            WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL AND id != $3
        )"
    )
    .bind(org_id)
    .bind(&payload.name)
    .bind(resource_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking name uniqueness: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
    })?;

    if name_exists == Some(true) {
        return Err((
            StatusCode::CONFLICT,
            format!("An app with the name '{}' already exists in this organization", payload.name),
        ));
    }

    // Update the resource name
    let updated_resource = sqlx::query_as::<_, ComputeResource>(
        "UPDATE compute_resources
         SET resource_name = $1
         WHERE id = $2 AND organization_id = $3
         RETURNING id, organization_id, provider_account_id, resource_type_id,
                   provider_resource_id, resource_name, state::text as state,
                   region, public_ip, configuration->>'domain' as domain,
                   billing_tag, configuration, created_at, updated_at"
    )
    .bind(&payload.name)
    .bind(resource_id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update resource name: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to rename resource".to_string())
    })?;

    // Rename the git repository if it exists
    let old_repo_path = format!("{}/git-repos/{}.git", state.data_dir, old_name);
    let new_repo_path = format!("{}/git-repos/{}.git", state.data_dir, payload.name);

    if tokio::fs::metadata(&old_repo_path).await.is_ok() {
        if let Err(e) = tokio::fs::rename(&old_repo_path, &new_repo_path).await {
            tracing::warn!(
                "Failed to rename git repo from {} to {}: {} (resource renamed in DB)",
                old_repo_path, new_repo_path, e
            );
        } else {
            tracing::info!("Renamed git repo from {} to {}", old_repo_path, new_repo_path);
        }
    }

    tracing::info!(
        "Resource {} renamed from '{}' to '{}' by user {}",
        resource_id, old_name, payload.name, auth.user_id
    );

    Ok(Json(updated_resource))
}

#[derive(Debug, Deserialize)]
struct DeleteResourceQuery {
    #[serde(default)]
    force: bool,
}

async fn delete_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    query: axum::extract::Query<DeleteResourceQuery>,
) -> Result<StatusCode, StatusCode> {
    tracing::info!("delete_resource called: resource_id={}, user_id={}, force={}", resource_id, auth.user_id, query.force);

    tracing::debug!("Querying resource access for user {} on resource {}", auth.user_id, resource_id);
    let resource: Option<(Uuid, Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT cr.id, cr.organization_id, cr.resource_name, pa.role_arn
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         INNER JOIN provider_accounts pa ON cr.provider_account_id = pa.id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database query failed in delete_resource: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some((_, org_id, resource_name, _role_arn_opt)) = resource else {
        tracing::warn!("Resource {} not found or user {} has no access", resource_id, auth.user_id);
        return Err(StatusCode::NOT_FOUND);
    };

    tracing::info!("Destroying resource {} (id: {})", resource_name, resource_id);

    let (aws_credentials, asg_name) = if let Some(encryptor) = state.encryptor.as_ref() {
        if let Ok(Some(credential)) = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id).await {
            if credential.managed_on_prem {
                if let Ok(Some(secrets)) = cloud_credentials::get_credential_secrets(&state.db, encryptor, org_id, credential.id).await {
                    let region = credential.config["aws_region"].as_str()
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("AWS_REGION").ok())
                        .unwrap_or_else(|| "us-west-2".to_string());
                    let asg = credential.config["asg_name"].as_str()
                        .map(|s| s.to_string());
                    (Some(deployment::AwsCredentials {
                        access_key_id: secrets["aws_access_key_id"].as_str().unwrap_or("").to_string(),
                        secret_access_key: secrets["aws_secret_access_key"].as_str().unwrap_or("").to_string(),
                        region,
                    }), asg)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let terraform_result = deployment::destroy_app_with_credentials(org_id, resource_id, resource_name.clone(), aws_credentials, asg_name).await;

    if let Err(ref e) = terraform_result {
        tracing::error!("Terraform destroy failed for resource {}: {}", resource_id, e);
        if !query.force {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::warn!("Force flag set - marking resource as destroyed despite Terraform failure. AWS resources may still exist!");
    }

    sqlx::query(
        "UPDATE compute_resources
         SET destroyed_at = NOW(), state = $1
         WHERE id = $2 AND organization_id = $3"
    )
    .bind(types::ResourceState::Terminated)
    .bind(resource_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Resource {} terminated by user {} (git repo preserved for redeployment)", resource_id, auth.user_id);

    Ok(StatusCode::NO_CONTENT)
}

async fn list_cloud_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cloud_credentials::CloudCredential>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credentials = cloud_credentials::list_credentials(&state.db, org_id).await?;
    Ok(Json(credentials))
}

async fn create_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cloud_credentials::CreateCredentialRequest>,
) -> Result<Json<cloud_credentials::CloudCredential>, (StatusCode, String)> {
    let encryptor = state.encryptor.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Cloud credentials feature not configured. Set CAUTION_ENCRYPTION_KEY.".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credential = cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req).await?;
    Ok(Json(credential))
}

async fn get_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<Json<cloud_credentials::CloudCredential>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credential = cloud_credentials::get_credential(&state.db, org_id, credential_id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Credential not found".to_string()))?;

    Ok(Json(credential))
}

async fn delete_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cloud_credentials::delete_credential(&state.db, org_id, credential_id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

async fn set_default_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let updated = cloud_credentials::set_default_credential(&state.db, org_id, credential_id).await?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

async fn list_quorum_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::QuorumBundle>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let items = cryptographic_bundles::list_quorum_bundles(&state.db, org_id).await?;
    Ok(Json(items))
}

async fn create_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::create_quorum_bundle(&state.db, org_id, auth.user_id, req).await?;
    Ok(Json(bundle))
}

async fn get_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::get_quorum_bundle(&state.db, org_id, id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn update_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::update_quorum_bundle(&state.db, org_id, id, req)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn delete_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cryptographic_bundles::delete_quorum_bundle(&state.db, org_id, id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))
    }
}

async fn list_secrets_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::SecretsBundle>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let items = cryptographic_bundles::list_secrets_bundles(&state.db, org_id).await?;
    Ok(Json(items))
}

async fn create_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::create_secrets_bundle(&state.db, org_id, auth.user_id, req).await?;
    Ok(Json(bundle))
}

async fn get_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::get_secrets_bundle(&state.db, org_id, id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn update_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::update_secrets_bundle(&state.db, org_id, id, req)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn delete_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cryptographic_bundles::delete_secrets_bundle(&state.db, org_id, id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))
    }
}

/// Get billing usage for the current billing period
async fn get_billing_usage(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Get all running resources for the org
    let resources: Vec<ComputeResource> = sqlx::query_as(
        "SELECT id, organization_id, provider_account_id, resource_type_id, provider_resource_id,
                resource_name, state::text as state, region, public_ip,
                configuration->>'domain' as domain, billing_tag, configuration,
                created_at, updated_at
         FROM compute_resources
         WHERE organization_id = $1 AND state = 'running'
         ORDER BY created_at DESC"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Verifiable compute margin (from prices.json, default 0%)
    let margin_percent = state.pricing.compute_margin_percent;

    // Base AWS on-demand rates by instance type (USD/hr, us-west-2)
    let get_base_rate = |instance_type: &str| -> f64 {
        match instance_type {
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
            _ => 0.20, // default rate
        }
    };

    use chrono::Datelike;
    let now = chrono::Utc::now();

    // Calculate billing period (first of current month to end of month)
    let first_of_month_naive = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap();
    let first_of_month_dt = first_of_month_naive.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let next_month_naive = if now.month() == 12 {
        chrono::NaiveDate::from_ymd_opt(now.year() + 1, 1, 1).unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(now.year(), now.month() + 1, 1).unwrap()
    };
    let days_in_month = next_month_naive.signed_duration_since(first_of_month_naive).num_days() as f64;
    let hours_in_month = days_in_month * 24.0;

    // Hours elapsed in the current billing period
    let hours_elapsed_in_period = now.signed_duration_since(first_of_month_dt).num_hours() as f64;

    let mut total_cost = 0.0;
    let mut total_projected = 0.0;
    let mut items = Vec::new();

    for resource in resources {
        // Hours in current billing period (resource may have started before this month)
        let resource_start_of_period = if resource.created_at > first_of_month_dt {
            resource.created_at
        } else {
            first_of_month_dt
        };
        let hours_this_period = now.signed_duration_since(resource_start_of_period).num_hours() as f64;

        // Get instance type from config
        let instance_type = resource.configuration
            .as_ref()
            .and_then(|c| c.get("instance_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let base_rate = get_base_rate(instance_type);
        let hourly_rate = base_rate * (1.0 + margin_percent / 100.0);
        let cost_this_period = hours_this_period.max(0.0) * hourly_rate;

        // Project: assume resource runs for the rest of the month
        let remaining_hours = hours_in_month - hours_elapsed_in_period;
        let projected_cost = cost_this_period + (remaining_hours.max(0.0) * hourly_rate);

        total_cost += cost_this_period;
        total_projected += projected_cost;

        items.push(serde_json::json!({
            "id": resource.id,
            "resource_id": resource.provider_resource_id,
            "resource_name": resource.resource_name.clone().unwrap_or_else(|| "Unnamed".to_string()),
            "resource_type": "compute",
            "instance_type": instance_type,
            "quantity": hours_this_period.max(0.0),
            "unit": "hours",
            "base_rate": format!("{:.3}", base_rate),
            "rate": format!("{:.2}", hourly_rate),
            "cost": cost_this_period,
            "projected_cost": projected_cost,
        }));
    }

    Ok(Json(serde_json::json!({
        "total_cost": total_cost,
        "projected_cost": total_projected,
        "currency": "USD",
        "billing_period_start": first_of_month_naive.to_string(),
        "billing_period_end": next_month_naive.to_string(),
        "items": items,
    })))
}

/// Get billing invoices
async fn get_billing_invoices(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Query invoices from database
    let invoices: Vec<(Uuid, String, i64, String, Option<String>, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT id, invoice_number, amount_cents, status, pdf_url, created_at
         FROM invoices
         WHERE organization_id = $1
         ORDER BY created_at DESC
         LIMIT 50"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let invoice_list: Vec<serde_json::Value> = invoices.iter().map(|(id, number, amount, status, pdf_url, date)| {
        serde_json::json!({
            "id": id,
            "number": number,
            "amount_cents": amount,
            "status": status,
            "pdf_url": pdf_url,
            "date": date.to_string(),
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "invoices": invoice_list,
    })))
}

/// Get all active payment methods
async fn get_payment_methods(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let rows: Vec<(Uuid, String, Option<String>, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, payment_type, last4, card_brand, email, is_primary
         FROM payment_methods
         WHERE organization_id = $1 AND is_active = true
         ORDER BY is_primary DESC, created_at DESC"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let methods: Vec<serde_json::Value> = rows.into_iter().map(|(id, payment_type, last4, card_brand, email, is_primary)| {
        serde_json::json!({
            "id": id,
            "type": payment_type,
            "last4": last4,
            "card_brand": card_brand,
            "email": email,
            "is_primary": is_primary,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "payment_methods": methods
    })))
}

/// Delete a specific payment method by ID
async fn delete_payment_method(
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
        return Err((StatusCode::NOT_FOUND, "Payment method not found".to_string()));
    };

    // Block deletion if this is the last active payment method and org has running resources
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true"
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if active_count <= 1 {
        return Err((StatusCode::CONFLICT,
            "You must have at least one payment method on file. Add another payment method before removing this one.".to_string()));
    }

    // Soft-delete
    sqlx::query(
        "UPDATE payment_methods SET is_active = false, is_primary = false WHERE id = $1"
    )
    .bind(method_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // If deleted method was primary, promote the most recent remaining card
    if was_primary {
        sqlx::query(
            "UPDATE payment_methods SET is_primary = true
             WHERE id = (
                SELECT id FROM payment_methods
                WHERE organization_id = $1 AND is_active = true
                ORDER BY created_at DESC LIMIT 1
             )"
        )
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Set a payment method as primary
async fn set_primary_payment_method(
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
        return Err((StatusCode::NOT_FOUND, "Payment method not found".to_string()));
    }

    // Unset primary on all org methods
    sqlx::query(
        "UPDATE payment_methods SET is_primary = false WHERE organization_id = $1 AND is_active = true"
    )
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Set primary on the specified method
    sqlx::query(
        "UPDATE payment_methods SET is_primary = true WHERE id = $1"
    )
    .bind(method_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Get Paddle client token and customer ID for frontend Paddle.js initialization
async fn get_paddle_client_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let client_token = state.paddle_client_token.as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Paddle is not configured".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Get the user's Paddle customer ID if one exists
    let paddle_customer_id: Option<String> = sqlx::query_scalar(
        "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .flatten();

    Ok(Json(serde_json::json!({
        "client_token": client_token,
        "paddle_customer_id": paddle_customer_id,
        "setup_price_id": state.paddle_setup_price_id,
    })))
}

#[derive(Deserialize)]
struct PaddleTransactionCompletedRequest {
    transaction_id: String,
    #[serde(default)]
    payment_method_id: Option<String>,
    #[serde(default)]
    card_last4: Option<String>,
    #[serde(default)]
    card_brand: Option<String>,
}

/// Frontend callback after Paddle checkout completion — records payment method reference locally
async fn paddle_transaction_completed(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PaddleTransactionCompletedRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Check if the org already has any active payment methods
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true"
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let is_primary = existing_count == 0;

    // Save the new payment method reference (keep existing methods active)
    sqlx::query(
        "INSERT INTO payment_methods (id, organization_id, payment_type, provider_token, paddle_payment_method_id, last4, card_brand, is_active, is_primary, created_at)
         VALUES ($1, $2, 'card', $3, $4, $5, $6, true, $7, NOW())"
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&req.transaction_id)
    .bind(&req.payment_method_id)
    .bind(&req.card_last4)
    .bind(&req.card_brand)
    .bind(is_primary)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Look up the Paddle customer ID from this transaction and store it
    if let Some(ref api_key) = state.paddle_api_key {
        if let Ok(customer_id) = fetch_paddle_customer_id_from_txn(
            &state.paddle_api_url, api_key, &req.transaction_id
        ).await {
            let _ = sqlx::query(
                "INSERT INTO billing_config (user_id, paddle_customer_id)
                 VALUES ($1, $2)
                 ON CONFLICT (user_id) DO UPDATE SET paddle_customer_id = $2"
            )
            .bind(auth.user_id)
            .bind(&customer_id)
            .execute(&state.db)
            .await;

            tracing::info!("Stored paddle_customer_id {} for user {}", customer_id, auth.user_id);
        }
    }

    tracing::info!(
        "Paddle transaction {} completed for org {}",
        req.transaction_id, org_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "transaction_id": req.transaction_id,
    })))
}

/// Fetch the customer_id from a Paddle transaction
async fn fetch_paddle_customer_id_from_txn(
    api_url: &str,
    api_key: &str,
    transaction_id: &str,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/transactions/{}", api_url, transaction_id))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("Paddle API error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Paddle API returned {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Parse error: {}", e))?;

    body["data"]["customer_id"].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No customer_id in transaction".to_string())
}

// --- Prepaid Credits ---

async fn get_credit_balance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "balance_cents": balance_cents,
        "balance_display": format!("${:.2}", balance_cents as f64 / 100.0),
    })))
}

async fn get_credit_packages(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let packages: Vec<serde_json::Value> = credit_packages.iter().map(|pkg| {
        serde_json::json!({
            "purchase_cents": pkg.purchase_cents,
            "credit_cents": pkg.credit_cents,
            "bonus_percent": pkg.bonus_percent,
            "purchase_display": format!("${}", pkg.purchase_cents / 100),
            "credit_display": format!("${}", pkg.credit_cents / 100),
            "paddle_price_id": pkg.paddle_price_id,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "packages": packages })))
}

#[derive(Deserialize)]
struct PurchaseCreditsRequest {
    /// Set by frontend after inline checkout completes (fallback flow)
    #[serde(default)]
    transaction_id: Option<String>,
    package_index: usize,
}

async fn purchase_credits(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<PurchaseCreditsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let credit_packages = build_credit_packages(&state.pricing, &state.paddle_credits_price_ids);
    let pkg = credit_packages.get(req.package_index)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid package index".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    // Determine the transaction_id — either provided by frontend (checkout flow)
    // or created server-side using saved payment method
    let transaction_id = if let Some(txn_id) = req.transaction_id {
        // Verify the transaction with Paddle before accepting
        let paddle_api_key = state.paddle_api_key.as_ref()
            .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured".to_string()))?;

        let client = reqwest::Client::new();
        let verify_resp = client
            .get(format!("{}/transactions/{}", state.paddle_api_url, txn_id))
            .header("Authorization", format!("Bearer {}", paddle_api_key))
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to verify transaction: {}", e)))?;

        if !verify_resp.status().is_success() {
            tracing::warn!("Paddle transaction verification failed for txn_id={}: {}", txn_id, verify_resp.status());
            return Err((StatusCode::BAD_REQUEST, "Invalid transaction ID".to_string()));
        }

        let verify_data: serde_json::Value = verify_resp.json().await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to parse Paddle response: {}", e)))?;

        let txn_status = verify_data["data"]["status"].as_str().unwrap_or("");
        if txn_status != "completed" && txn_status != "paid" && txn_status != "billed" {
            tracing::warn!("Paddle transaction {} has status '{}', not completed", txn_id, txn_status);
            return Err((StatusCode::PAYMENT_REQUIRED, format!("Transaction not completed (status: {})", txn_status)));
        }

        txn_id
    } else {
        // Try to charge the card on file via Paddle API
        let paddle_api_key = state.paddle_api_key.as_ref()
            .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Paddle API not configured".to_string()))?;

        // Try billing_config first, then resolve from an existing payment method transaction
        let mut paddle_customer_id: Option<String> = sqlx::query_scalar(
            "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .flatten();

        // If no billing_config row, resolve customer_id from an existing payment method's transaction
        if paddle_customer_id.is_none() {
            let existing_txn: Option<String> = sqlx::query_scalar(
                "SELECT provider_token FROM payment_methods
                 WHERE organization_id = $1 AND is_active = true AND provider_token IS NOT NULL
                 LIMIT 1"
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

            if let Some(txn_id) = existing_txn {
                if let Ok(cid) = fetch_paddle_customer_id_from_txn(
                    &state.paddle_api_url, paddle_api_key, &txn_id
                ).await {
                    // Cache it in billing_config for future use
                    let _ = sqlx::query(
                        "INSERT INTO billing_config (user_id, paddle_customer_id)
                         VALUES ($1, $2)
                         ON CONFLICT (user_id) DO UPDATE SET paddle_customer_id = $2"
                    )
                    .bind(auth.user_id)
                    .bind(&cid)
                    .execute(&state.db)
                    .await;

                    tracing::info!("Resolved and cached paddle_customer_id {} for org {}", cid, org_id);
                    paddle_customer_id = Some(cid);
                }
            }
        }

        let customer_id = paddle_customer_id
            .ok_or_else(|| (StatusCode::PAYMENT_REQUIRED, "no_payment_method".to_string()))?;

        // Get price ID for this package
        let price_id = state.paddle_credits_price_ids[req.package_index].as_ref()
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Credit package price not configured".to_string()))?;

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
            return Err((StatusCode::BAD_GATEWAY, format!("Paddle payment failed: {}", status)));
        }

        let resp: serde_json::Value = response.json().await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Paddle response parse error: {}", e)))?;

        let txn_id = resp["data"]["id"].as_str()
            .ok_or_else(|| (StatusCode::BAD_GATEWAY, "Missing transaction ID in Paddle response".to_string()))?
            .to_string();

        tracing::info!("Created Paddle transaction {} for credit purchase (card on file)", txn_id);
        txn_id
    };

    // Idempotency: check if this transaction was already processed
    let already_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credit_ledger WHERE paddle_transaction_id = $1)"
    )
    .bind(&transaction_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if already_exists {
        let balance_cents: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

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
        auth.user_id,
        pkg.credit_cents,
        "purchase",
        &description,
        Some(&transaction_id),
        None,
    ).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to apply credit: {}", e)))?;

    tracing::info!(
        "Credit purchase: user={}, txn={}, +{} cents, new_balance={}",
        auth.user_id, transaction_id, pkg.credit_cents, new_balance
    );

    // Check if org was credit-suspended and unsuspend if balance is now positive
    if new_balance > 0 {
        if let Ok(org_id) = get_user_primary_org(&state.db, auth.user_id).await {
            let suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                "SELECT credit_suspended_at FROM organizations WHERE id = $1"
            )
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .flatten();

            if suspended.is_some() {
                tracing::info!("Clearing credit suspension for org {} after credit purchase", org_id);
                let _ = sqlx::query(
                    "UPDATE organizations SET credit_suspended_at = NULL WHERE id = $1"
                )
                .bind(org_id)
                .execute(&state.db)
                .await;

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

async fn get_credit_ledger(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rows: Vec<(Uuid, i64, i64, String, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, delta_cents, balance_after, entry_type, description, paddle_transaction_id, created_at
         FROM credit_ledger
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 50"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let entries: Vec<serde_json::Value> = rows.into_iter().map(|(id, delta, balance_after, entry_type, desc, txn_id, created_at)| {
        serde_json::json!({
            "id": id,
            "delta_cents": delta,
            "balance_after": balance_after,
            "entry_type": entry_type,
            "description": desc,
            "paddle_transaction_id": txn_id,
            "created_at": created_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "entries": entries })))
}

async fn redeem_credit_code(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let code = body.get("code")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'code' field".to_string()))?
        .trim()
        .replace('-', "");

    if code.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Code cannot be empty".to_string()));
    }

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

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
            return Err((StatusCode::NOT_FOUND, "Invalid or already redeemed code".to_string()));
        }
    };

    sqlx::query("UPDATE credit_codes SET redeemed_by = $1, redeemed_at = NOW() WHERE id = $2")
        .bind(auth.user_id)
        .bind(code_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Apply credits within the same transaction so redemption + credit are atomic
    let new_balance: i64 = sqlx::query_scalar(
        "INSERT INTO wallet_balance (user_id, balance_cents)
         VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET balance_cents = wallet_balance.balance_cents + $2
         RETURNING balance_cents"
    )
    .bind(auth.user_id)
    .bind(amount_cents)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to apply credit: {}", e)))?;

    sqlx::query(
        "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description)
         VALUES ($1, $2, $3, 'code_redemption', 'Redeemed credit code')"
    )
    .bind(auth.user_id)
    .bind(amount_cents)
    .bind(new_balance)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record ledger entry: {}", e)))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    tracing::info!(
        "Credit code redeemed: user={}, code_id={}, +{} cents, new_balance={}",
        auth.user_id, code_id, amount_cents, new_balance
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "amount_cents": amount_cents,
        "new_balance": new_balance,
    })))
}

/// Atomically upsert wallet_balance and insert a credit_ledger row.
/// Returns the new balance.
async fn apply_credit(
    db: &PgPool,
    user_id: Uuid,
    delta_cents: i64,
    entry_type: &str,
    description: &str,
    paddle_txn_id: Option<&str>,
    invoice_id: Option<Uuid>,
) -> Result<i64, String> {
    let mut tx = db.begin().await.map_err(|e| format!("Failed to begin transaction: {}", e))?;

    let new_balance: i64 = sqlx::query_scalar(
        "INSERT INTO wallet_balance (user_id, balance_cents)
         VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET balance_cents = wallet_balance.balance_cents + $2
         RETURNING balance_cents"
    )
    .bind(user_id)
    .bind(delta_cents)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to upsert wallet_balance: {}", e))?;

    sqlx::query(
        "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description, paddle_transaction_id, invoice_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(user_id)
    .bind(delta_cents)
    .bind(new_balance)
    .bind(entry_type)
    .bind(description)
    .bind(paddle_txn_id)
    .bind(invoice_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to insert credit_ledger: {}", e))?;

    tx.commit().await.map_err(|e| format!("Failed to commit transaction: {}", e))?;

    Ok(new_balance)
}

// --- Managed On-Prem Subscriptions ---

async fn get_subscription_tiers(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let discounts = &state.pricing.billing_discounts;
    let extra_block_annual = state.pricing.extra_block_annual_cents;

    let tiers: Vec<serde_json::Value> = SUBSCRIPTION_TIERS.iter().map(|t| {
        let annual_cents = state.pricing.tier_annual_cents(t.id);
        serde_json::json!({
            "id": t.id,
            "name": t.name,
            "annual_cents": annual_cents,
            "max_vcpus": t.max_vcpus,
            "max_apps": t.max_apps,
            "prices": {
                "monthly": calculate_cycle_price(annual_cents, "monthly", discounts),
                "yearly": calculate_cycle_price(annual_cents, "yearly", discounts),
                "2year": calculate_cycle_price(annual_cents, "2year", discounts),
            },
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "tiers": tiers,
        "extra_block": {
            "annual_cents": extra_block_annual,
            "vcpus": 64,
            "apps": 10,
            "prices": {
                "monthly": calculate_cycle_price(extra_block_annual, "monthly", discounts),
                "yearly": calculate_cycle_price(extra_block_annual, "yearly", discounts),
                "2year": calculate_cycle_price(extra_block_annual, "2year", discounts),
            },
        },
    })))
}

async fn get_subscription(
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
    let tier_info = SUBSCRIPTION_TIERS.iter().find(|t| t.id == tier);

    Ok(Json(serde_json::json!({
        "subscription": {
            "id": row.get::<Uuid, _>("id"),
            "user_id": row.get::<Uuid, _>("user_id"),
            "organization_id": row.get::<Uuid, _>("organization_id"),
            "tier": tier,
            "tier_name": tier_info.map(|t| t.name).unwrap_or("Unknown"),
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
struct SubscribeRequest {
    tier_id: String,
    #[serde(default = "default_billing_period")]
    billing_period: String,
}

fn default_billing_period() -> String { "monthly".to_string() }

async fn subscribe(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tier = SUBSCRIPTION_TIERS.iter().find(|t| t.id == req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

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
    let annual_cents = state.pricing.tier_annual_cents(tier.id);
    let price_per_cycle = calculate_cycle_price(annual_cents, &req.billing_period, &state.pricing.billing_discounts);
    let period_end = calculate_period_end(now, &req.billing_period);

    // Charge first period: credits first, then Paddle for remainder
    let total_charge = price_per_cycle;

    // Check credit balance
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
    .unwrap_or(0);

    let credits_to_apply = balance_cents.min(total_charge).max(0);
    let remainder_cents = total_charge - credits_to_apply;

    // If Paddle charge is needed, do it BEFORE creating the subscription
    let mut paddle_txn_id: Option<String> = None;
    let event_status;

    if remainder_cents > 0 {
        let paddle_customer_id: Option<String> = sqlx::query_scalar(
            "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .flatten();

        if let Some(customer_id) = paddle_customer_id {
            if let Some(ref api_key) = state.paddle_api_key {
                let client = reqwest::Client::new();
                let amount_str = remainder_cents.to_string();
                let body = serde_json::json!({
                    "customer_id": customer_id,
                    "items": [{
                        "quantity": 1,
                        "price": {
                            "description": format!("{} subscription ({})", tier.name, req.billing_period),
                            "unit_price": {
                                "amount": amount_str,
                                "currency_code": "USD",
                            },
                            "product": {
                                "name": format!("{} Subscription", tier.name),
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
    .bind(tier.id)
    .bind(&req.billing_period)
    .bind(tier.max_vcpus)
    .bind(tier.max_apps)
    .bind(price_per_cycle)
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create subscription: {}", e)))?;

    // Deduct credits within the transaction
    if credits_to_apply > 0 {
        sqlx::query(
            "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE user_id = $2"
        )
        .bind(credits_to_apply)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deduct credits: {}", e)))?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT balance_cents FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        sqlx::query(
            "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'billing_deduction', $4)"
        )
        .bind(auth.user_id)
        .bind(-credits_to_apply)
        .bind(new_balance)
        .bind(format!("Subscription: {} {}", tier.name, req.billing_period))
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
    .bind(tier.id)
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
        "INSERT INTO invoices (paddle_transaction_id, user_id, invoice_number, amount_cents, currency, status, payment_status, billing_provider, created_at)
         VALUES ($1, $2, $3, $4, 'USD', 'finalized', $5, $6, NOW())"
    )
    .bind(&paddle_txn_id)
    .bind(auth.user_id)
    .bind(&invoice_number)
    .bind(total_charge)
    .bind(if remainder_cents == 0 { "credits_applied" } else { "paid" })
    .bind(if remainder_cents == 0 { "credits" } else { "paddle" })
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to record invoice: {}", e)))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit: {}", e)))?;

    tracing::info!(
        "Subscription created: sub={}, tier={}, org={}, charge={} cents (credits={}, paddle={})",
        sub_id.0, tier.id, org_id, total_charge, credits_to_apply, remainder_cents
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "subscription_id": sub_id.0,
        "tier": tier.id,
        "billing_period": req.billing_period,
        "price_cents_per_cycle": price_per_cycle,
        "credits_applied": credits_to_apply,
        "charged": remainder_cents,
    })))
}

#[derive(Deserialize)]
struct ChangeTierRequest {
    tier_id: String,
}

async fn change_subscription_tier(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ChangeTierRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let new_tier = SUBSCRIPTION_TIERS.iter().find(|t| t.id == req.tier_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid tier".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let sub: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, billing_period FROM subscriptions WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let Some((sub_id, billing_period)) = sub else {
        return Err((StatusCode::NOT_FOUND, "No active subscription".to_string()));
    };

    let new_annual_cents = state.pricing.tier_annual_cents(new_tier.id);
    let new_price = calculate_cycle_price(new_annual_cents, &billing_period, &state.pricing.billing_discounts);

    // Change takes effect at next billing cycle
    sqlx::query(
        "UPDATE subscriptions SET tier = $1, max_vcpus = $2, max_apps = $3, price_cents_per_cycle = $4, updated_at = NOW()
         WHERE id = $5"
    )
    .bind(new_tier.id)
    .bind(new_tier.max_vcpus)
    .bind(new_tier.max_apps)
    .bind(new_price)
    .bind(sub_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    tracing::info!("Subscription {} tier changed to {} (takes effect next cycle)", sub_id, new_tier.id);

    Ok(Json(serde_json::json!({
        "success": true,
        "new_tier": new_tier.id,
        "new_price_cents_per_cycle": new_price,
        "effective": "next_billing_cycle",
    })))
}

#[derive(Deserialize)]
struct AddCapacityRequest {
    vcpu_blocks: Option<i32>,
    app_blocks: Option<i32>,
}

async fn add_subscription_capacity(
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

    let block_price_per_cycle = calculate_cycle_price(state.pricing.extra_block_annual_cents, &billing_period, &state.pricing.billing_discounts);
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
    let mut credits_applied = 0i64;
    if prorated_charge > 0 {
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        credits_applied = balance.min(prorated_charge).max(0);
        let remainder = prorated_charge - credits_applied;

        if remainder > 0 {
            // Charge via Paddle — must succeed before we update capacity
            let paddle_customer_id: Option<String> = sqlx::query_scalar(
                "SELECT paddle_customer_id FROM billing_config WHERE user_id = $1"
            )
            .bind(auth.user_id)
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
    .bind(add_vcpu * 64)
    .bind(add_app * 10)
    .bind(sub_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if credits_applied > 0 {
        sqlx::query(
            "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE user_id = $2"
        )
        .bind(credits_applied)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deduct credits: {}", e)))?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT balance_cents FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        sqlx::query(
            "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'billing_deduction', 'Subscription capacity addon (prorated)')"
        )
        .bind(auth.user_id)
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

async fn cancel_subscription(
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

async fn reactivate_subscription(
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

/// Create or update a managed on-prem resource.
/// Accepts either plain JSON or GPG-encrypted config from the setup script.
/// If resource_id is provided, updates the existing resource; otherwise creates a new one.
async fn create_managed_onprem_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let json_content = if gpg::is_gpg_encrypted(&body) {
        tracing::info!("Received GPG-encrypted managed on-prem config, decrypting...");
        let decrypted = gpg::decrypt_gpg_message(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("GPG decryption failed: {}", e)))?;
        tracing::info!("GPG decryption successful");
        decrypted
    } else {
        body
    };

    let mut req: cloud_credentials::CreateCredentialRequest = serde_json::from_str(&json_content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?;

    if !req.managed_on_prem {
        return Err((StatusCode::BAD_REQUEST, "This endpoint requires managed_on_prem: true".to_string()));
    }

    let deployment_id = req.deployment_id.clone()
        .ok_or((StatusCode::BAD_REQUEST, "deployment_id is required".to_string()))?;

    let encryptor = state.encryptor.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Encryption not configured. Set CAUTION_ENCRYPTION_KEY.".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let managed_onprem_config = serde_json::json!({
        "deployment_id": req.deployment_id,
        "asg_name": req.asg_name,
        "launch_template_name": req.launch_template_name,
        "launch_template_id": req.launch_template_id,
        "vpc_id": req.vpc_id,
        "subnet_ids": req.subnet_ids,
        "eif_bucket": req.eif_bucket,
        "instance_profile_name": req.instance_profile_name,
        "aws_region": req.aws_region,
        "aws_account_id": req.aws_account_id,
    });

    let configuration = serde_json::json!({
        "managed_onprem": managed_onprem_config,
    });

    if let Some(existing_resource_id) = req.resource_id {
        tracing::info!(
            "Updating managed on-prem resource {}: deployment_id={}",
            existing_resource_id, deployment_id
        );

        let existing: Option<(String, types::ResourceState)> = sqlx::query_as(
            "SELECT resource_name, state FROM compute_resources
             WHERE id = $1 AND organization_id = $2"
        )
        .bind(existing_resource_id)
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        let (resource_name, resource_state) = existing
            .ok_or((StatusCode::NOT_FOUND, format!("Resource {} not found", existing_resource_id)))?;

        sqlx::query(
            "UPDATE compute_resources SET configuration = $1, updated_at = NOW()
             WHERE id = $2 AND organization_id = $3"
        )
        .bind(&configuration)
        .bind(existing_resource_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

        sqlx::query("DELETE FROM cloud_credentials WHERE resource_id = $1 AND organization_id = $2")
            .bind(existing_resource_id)
            .bind(org_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete old credential: {}", e)))?;

        let credential = cloud_credentials::create_credential(
            &state.db, encryptor, org_id, auth.user_id, req
        ).await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, existing_resource_id),
            None => format!("git@{}:{}.git", state.git_hostname, existing_resource_id),
        };

        tracing::info!(
            "Updated managed on-prem resource {}: credential_id={}, deployment_id={}",
            existing_resource_id, credential.id, deployment_id
        );

        Ok(Json(serde_json::json!({
            "id": existing_resource_id,
            "resource_name": resource_name,
            "git_url": git_url,
            "state": resource_state.as_str(),
            "credential_id": credential.id,
            "managed_onprem": managed_onprem_config,
            "updated": true,
        })))
    } else {
        tracing::info!(
            "Creating managed on-prem resource: deployment_id={}",
            deployment_id
        );

        let provider_account_id = get_or_create_provider_account(&state.db, org_id)
            .await
            .map_err(|e| (e, "Failed to get provider account".to_string()))?;

        let resource_type_id = get_or_create_resource_type(&state.db)
            .await
            .map_err(|e| (e, "Failed to get resource type".to_string()))?;

        let provider_resource_id = Uuid::new_v4().to_string();
        let resource_slug = format!("app-{}", &provider_resource_id[..8]);

        // Create the resource first (so we have a resource_id for the credential)
        let resource: (Uuid, types::ResourceState, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO compute_resources
             (organization_id, provider_account_id, resource_type_id, provider_resource_id,
              resource_name, state, configuration, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, state, created_at"
        )
        .bind(org_id)
        .bind(provider_account_id)
        .bind(resource_type_id)
        .bind(&provider_resource_id)
        .bind(&resource_slug)
        .bind(types::ResourceState::Pending)
        .bind(&configuration)
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error creating resource: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create resource: {}", e))
        })?;

        let (resource_id, resource_state, created_at) = resource;

        req.resource_id = Some(resource_id);

        let credential = cloud_credentials::create_credential(
            &state.db, encryptor, org_id, auth.user_id, req
        ).await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
            None => format!("git@{}:{}.git", state.git_hostname, resource_id),
        };

        tracing::info!(
            "Created managed on-prem resource {}: credential_id={}, deployment_id={}",
            resource_id, credential.id, deployment_id
        );

        Ok(Json(serde_json::json!({
            "id": resource_id,
            "resource_name": resource_slug,
            "git_url": git_url,
            "state": resource_state.as_str(),
            "created_at": created_at,
            "credential_id": credential.id,
            "managed_onprem": managed_onprem_config,
        })))
    }
}

fn milestone(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("STEP:{}\n", msg))
}

fn milestone_done(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("{}\n", msg))
}

fn milestone_error(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("error: {}\n", msg))
}

async fn deploy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(req): validated_types::Validated<DeployRequest>,
) -> Response {
    use tokio::process::Command;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);

    // Spawn the deploy logic in a separate task
    tokio::spawn(async move {
        let result = deploy_logic(state, auth, req, tx.clone()).await;

        // Send final result as JSON
        match result {
            Ok(response) => {
                let json = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", json)))).await;
            }
            Err((status, msg)) => {
                let _ = tx.send(Ok(milestone_error(&msg))).await;
                let error_json = serde_json::json!({"error": msg, "status": status.as_u16()});
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", error_json)))).await;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(body)
        .unwrap()
}

async fn deploy_logic(
    state: Arc<AppState>,
    auth: AuthContext,
    req: DeployRequest,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
) -> Result<DeployResponse, (StatusCode, String)> {
    use tokio::process::Command;

    tracing::info!(
        "Deployment request: user_id={}, org_id={}, app_id={}",
        auth.user_id,
        req.org_id,
        req.app_id
    );

    let app_id_str = req.app_id.to_string();

    let user_in_org: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM organization_members 
            WHERE user_id = $1 AND organization_id = $2
        )"
    )
    .bind(auth.user_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;
    
    if user_in_org != Some(true) {
        return Err((
            StatusCode::FORBIDDEN,
            "User does not belong to this organization".to_string(),
        ));
    }

    let _ = tx.send(Ok(milestone("Preparing deployment..."))).await;

    tracing::info!("Fetching provider account for org {}", req.org_id);
    let provider_account: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, external_account_id, role_arn
         FROM provider_accounts
         WHERE organization_id = $1 AND is_active = true
         LIMIT 1"
    )
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch provider account: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error fetching provider account: {}", e))
    })?;

    tracing::info!("Provider account query result: {:?}", provider_account);

    let (provider_account_id, aws_account_id_opt, role_arn_opt) = provider_account
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "No active provider account found".to_string()))?;

    tracing::info!("Provider account details: id={}, aws_account_id={:?}, role_arn={:?}",
                   provider_account_id, aws_account_id_opt, role_arn_opt);

    let aws_account_id = aws_account_id_opt
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Provider account has no AWS account ID configured".to_string()))?;

    if let Some(ref role_arn) = role_arn_opt {
        tracing::info!("Deploying to AWS account {} via role {}", aws_account_id, role_arn);
    } else {
        tracing::info!("Deploying to root AWS account {} (no role assumption)", aws_account_id);
    }

    tracing::info!("Fetching resource type for EC2Instance");
    let resource_type_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM resource_types WHERE type_code = $1 LIMIT 1"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get resource type: {}", e)))?;

    tracing::info!("Looking up resource by id={}", req.app_id);
    let existing_resource: Option<(Uuid, Option<String>, Option<serde_json::Value>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, resource_name, configuration, destroyed_at FROM compute_resources
         WHERE id = $1 AND organization_id = $2"
    )
    .bind(req.app_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check existing resource: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error checking existing resource: {}", e))
    })?;

    let (resource_id, app_name, configuration, was_destroyed) = match &existing_resource {
        Some((id, name_opt, config_opt, destroyed_at)) => {
            let name = name_opt.clone().unwrap_or_else(|| "unnamed".to_string());
            let config = config_opt.clone().unwrap_or_else(|| serde_json::json!({}));
            (*id, name, config, destroyed_at.is_some())
        }
        None => return Err((StatusCode::NOT_FOUND, format!("App with id {} not found", req.app_id))),
    };

    tracing::info!("Found resource: id={}, name={}", resource_id, app_name);

    // --- Billing gate (pre-deploy) --- must run before reactivation to avoid side effects on failure
    let cred = cloud_credentials::get_credential_by_resource(&state.db, req.org_id, resource_id).await?;
    let is_managed_onprem = cred.as_ref().map(|c| c.managed_on_prem).unwrap_or(false);

    if is_managed_onprem {
        // Managed on-prem: require active subscription with capacity
        let sub: Option<(Uuid, i32)> = sqlx::query_as(
            "SELECT id, max_apps FROM subscriptions
             WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        let Some((sub_id, max_apps)) = sub else {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises deployment requires an active subscription. Choose a plan in Settings at https://caution.dev".to_string()));
        };

        // Count current managed on-prem apps (exclude this resource if redeploying)
        let current_apps: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc ON cc.resource_id = cr.id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.state != 'terminated' AND cr.id != $2"
        )
        .bind(req.org_id)
        .bind(resource_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        // +1 for the app being deployed
        if current_apps + 1 > max_apps as i64 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                format!("App limit reached ({}/{}). Upgrade your plan or add capacity in Settings at https://caution.dev",
                    current_apps + 1, max_apps)));
        }

        tracing::info!("Billing gate passed: managed on-prem app {}/{}, sub={}", current_apps + 1, max_apps, sub_id);
    } else {
        // Fully managed: require >= $5 (500 cents) in wallet credits
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        if balance < 500 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                format!("Minimum $5.00 in credits required to deploy (current balance: ${:.2}). \
                         Purchase credits at https://caution.dev/settings/billing",
                         balance as f64 / 100.0)));
        }

        // Block deploy if org is credit-suspended (awaiting credit deposit)
        let credit_suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT credit_suspended_at FROM organizations WHERE id = $1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .flatten();

        if credit_suspended.is_some() {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "Your organization is suspended due to credit exhaustion. \
                 Add credits at https://caution.dev/settings/billing to resume.".to_string()));
        }

        tracing::info!("Billing gate passed: fully managed, balance_cents={}", balance);
    }

    if was_destroyed {
        tracing::info!("Reactivating previously destroyed resource {}", resource_id);
        sqlx::query("UPDATE compute_resources SET destroyed_at = NULL, state = $1 WHERE id = $2 AND organization_id = $3")
            .bind(types::ResourceState::Pending)
            .bind(resource_id)
            .bind(req.org_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reactivate resource: {}", e)))?;
    }

    tracing::info!("Deploying branch: {}", req.branch);

    let commit_sha = match get_commit_sha(&app_id_str, &req.branch, &state.data_dir).await {
        Ok(sha) => {
            tracing::info!("Latest commit on branch '{}': {}", req.branch, sha);
            sha
        }
        Err(e) => {
            tracing::error!("Failed to get commit SHA for branch '{}': {:?}", req.branch, e);
            return Err((StatusCode::BAD_REQUEST, format!("Failed to get commit SHA for branch '{}': {}", req.branch, e)));
        }
    };

    let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);
    let procfile_output = Command::new("git")
        .args(&["--git-dir", &git_dir, "show", &format!("{}:Procfile", commit_sha)])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run git show for Procfile: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
        })?;

    let build_config = if procfile_output.status.success() {
        let content = String::from_utf8_lossy(&procfile_output.stdout);
        match types::BuildConfig::from_procfile(&content) {
            Ok(config) => {
                tracing::info!("Loaded build config from Procfile: containerfile={:?}, binary={:?}, build={:?}, oci_tarball={:?}",
                               config.containerfile, config.binary, config.build, config.oci_tarball);
                config
            }
            Err(e) => {
                tracing::error!("Failed to parse Procfile: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid Procfile: {}", e),
                ));
            }
        }
    } else {
        tracing::error!("Procfile not found in repository at commit {}", commit_sha);
        return Err((
            StatusCode::BAD_REQUEST,
            "No Procfile found in repository root. Please add a Procfile with 'containerfile', 'binary', and 'run' fields.".to_string(),
        ));
    };

    // Get build command from the resource configuration
    let build_command = configuration.get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("docker build -t app .")
        .to_string();
    tracing::info!("Using resource {} with build command: {}", resource_id, build_command);

    tracing::info!("Build command for {}: {}", app_name, build_command);

    let cache_dir = format!("{}/build/{}", state.data_dir, req.org_id);
    let cache_dir_str = cache_dir.clone();
    tokio::fs::create_dir_all(&cache_dir).await.map_err(|e| {
        tracing::error!("Failed to create cache directory: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create cache directory: {}", e))
    })?;

    let image_tarball = format!("{}/{}-{}.tar", cache_dir_str, app_id_str, commit_sha);
    let tarball_exists = tokio::fs::metadata(&image_tarball).await.is_ok() && !build_config.no_cache;

    let image_name = format!("caution-{}:{}", app_id_str, &commit_sha[..12]);

    if build_config.no_cache {
        tracing::info!("Cache disabled (no_cache=true), forcing rebuild");
    }

    let _ = tx.send(Ok(milestone("Building Docker image..."))).await;

    if tarball_exists {
        tracing::info!("Cache HIT: Using cached tarball for commit {}", commit_sha);

        tracing::info!("Loading cached image into Docker: {}", image_name);
        let load_output = Command::new("docker")
            .args(&["load", "-i", &image_tarball])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to load cached image: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load cached image: {}", e))
            })?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            tracing::error!("Docker load failed: {}", stderr);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load cached image: {}", stderr)));
        }

        let load_stdout = String::from_utf8_lossy(&load_output.stdout);
        tracing::info!("Cached image loaded successfully. Docker load output: {}", load_stdout);

        let inspect_output = Command::new("docker")
            .args(&["inspect", "--type=image", &image_name])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to inspect image: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to inspect image: {}", e))
            })?;

        if !inspect_output.status.success() {
            tracing::warn!("Loaded cached image doesn't have expected tag {}, attempting to parse and tag", image_name);

            if let Some(loaded_line) = load_stdout.lines().find(|l| l.contains("Loaded image")) {
                let loaded_image = if loaded_line.contains("Loaded image ID:") {
                    loaded_line.split("Loaded image ID:").nth(1).map(|s| s.trim().to_string())
                } else if loaded_line.contains("Loaded image:") {
                    loaded_line.split("Loaded image:").nth(1).map(|s| s.trim().to_string())
                } else {
                    None
                };

                if let Some(loaded_img) = loaded_image {
                    tracing::info!("Tagging loaded image {} as {}", loaded_img, image_name);

                    let tag_output = Command::new("docker")
                        .args(&["tag", &loaded_img, &image_name])
                        .output()
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to tag cached image: {:?}", e);
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to tag cached image: {}", e))
                        })?;

                    if !tag_output.status.success() {
                        let stderr = String::from_utf8_lossy(&tag_output.stderr);
                        tracing::error!("Failed to tag cached image: {}", stderr);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to tag cached image: {}", stderr)));
                    }

                    tracing::info!("Successfully tagged cached image as {}", image_name);
                } else {
                    tracing::error!("Could not parse loaded image name from: {}", loaded_line);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to parse loaded image name".to_string()));
                }
            } else {
                tracing::error!("Docker load output didn't contain 'Loaded image' line");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Invalid docker load output".to_string()));
            }
        } else {
            tracing::info!("Cached image already has correct tag: {}", image_name);
        }
    } else {
        tracing::info!("Cache MISS: Building Docker image for commit {}", commit_sha);

        let build_commit_sha = match build_image_from_repo(&app_id_str, &build_config, &image_name, &req.branch, &state.data_dir).await {
            Ok(sha) => {
                tracing::info!("Successfully built image: {} (commit: {})", image_name, sha);
                sha
            }
            Err(e) => {
                tracing::error!("Failed to build image: {:?}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Image build failed: {}", e)));
            }
        };

        if build_commit_sha != commit_sha {
            tracing::warn!("Commit SHA mismatch: expected {}, got {}", commit_sha, build_commit_sha);
        }

        tracing::info!("Exporting image to tarball: {}", image_tarball);
        match export_image_to_tarball(&image_name, &image_tarball).await {
            Ok(()) => {
                tracing::info!("Exported image to: {}", image_tarball);
            }
            Err(e) => {
                tracing::error!("Failed to export image: {:?}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Image export failed: {}", e)));
            }
        }
    }

    let _ = tx.send(Ok(milestone("Building enclave image..."))).await;

    tracing::info!("Building Nitro Enclave EIF for commit {}", commit_sha);

    let containerfile = if let Some(cf) = build_config.containerfile.clone() {
        cf
    } else if build_config.build.is_none() {
        let containerfile_check = Command::new("git")
            .args(&["--git-dir", &git_dir, "show", &format!("{}:Containerfile", commit_sha)])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to check for Containerfile: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
            })?;

        if containerfile_check.status.success() {
            "Containerfile".to_string()
        } else {
            let dockerfile_check = Command::new("git")
                .args(&["--git-dir", &git_dir, "show", &format!("{}:Dockerfile", commit_sha)])
                .output()
                .await
                .map_err(|e| {
                    tracing::error!("Failed to check for Dockerfile: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
                })?;

            if dockerfile_check.status.success() {
                "Dockerfile".to_string()
            } else {
                tracing::error!("No Containerfile or Dockerfile found at commit {}", commit_sha);
                return Err((
                    StatusCode::BAD_REQUEST,
                    "No Containerfile or Dockerfile found in repository root".to_string(),
                ));
            }
        }
    } else {
        "Dockerfile".to_string()
    };

    let work_dir = format!("{}/build/work-{}-{}", state.data_dir, app_id_str, commit_sha);
    if build_config.no_cache {
        if let Err(e) = tokio::fs::remove_dir_all(&work_dir).await {
            tracing::debug!("Could not remove work_dir (may not exist): {}", e);
        }
    }
    tokio::fs::create_dir_all(&work_dir).await.map_err(|e| {
        tracing::error!("Failed to create work directory: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create work directory: {}", e))
    })?;

    let mut git_archive = Command::new("git")
        .args(["--git-dir", &git_dir, "archive", &commit_sha])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            tracing::error!("Failed to spawn git archive: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let git_stdout = git_archive.stdout.take().expect("piped stdout")
        .into_owned_fd().map_err(|e| {
            tracing::error!("Failed to get git stdout fd: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let tar_output = Command::new("tar")
        .args(["-xC", &work_dir])
        .stdin(git_stdout)
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run tar extract: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let git_status = git_archive.wait().await.map_err(|e| {
        tracing::error!("Failed to wait for git archive: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
    })?;

    if !git_status.success() {
        tracing::error!("git archive failed with status {}", git_status);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract repository".to_string()));
    }

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        tracing::error!("tar extract failed: {}", stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract repository".to_string()));
    }

    let _containerfile_path = format!("{}/{}", work_dir, containerfile);

    let enclave_config = types::EnclaveConfig {
        binary_path: build_config.binary.clone().unwrap_or_else(|| "/app".to_string()),
        args: vec![],
        memory_mb: build_config.memory_mb,
        cpus: build_config.cpus,
        debug: build_config.debug,
        ports: build_config.ports.clone(),
        http_port: build_config.http_port,
    };

    // --- Billing gate: vCPU check (post-Procfile parse, managed on-prem only) ---
    if is_managed_onprem {
        let sub_vcpus: Option<(i32,)> = sqlx::query_as(
            "SELECT max_vcpus FROM subscriptions
             WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        if let Some((max_vcpus,)) = sub_vcpus {
            let used_vcpus: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM((cr.configuration->>'vcpus')::int), 0)
                 FROM compute_resources cr
                 JOIN cloud_credentials cc ON cc.resource_id = cr.id
                 WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
                   AND cr.state = 'running' AND cr.id != $2"
            )
            .bind(req.org_id)
            .bind(resource_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

            let requested_vcpus = enclave_config.cpus as i64;
            if used_vcpus + requested_vcpus > max_vcpus as i64 {
                return Err((StatusCode::PAYMENT_REQUIRED,
                    format!("vCPU limit would be exceeded ({}+{}/{}). Upgrade your plan or add capacity in Settings at https://caution.dev",
                        used_vcpus, requested_vcpus, max_vcpus)));
            }
            tracing::info!("vCPU gate passed: {}+{}/{}", used_vcpus, requested_vcpus, max_vcpus);
        }
    }

    let prebuilt_eif_path = format!("{}/nitro.eif", work_dir);
    let prebuilt_pcrs_path = format!("{}/nitro.pcrs", work_dir);

    let cached_eif_path = format!("{}/{}-{}.eif", cache_dir_str, app_id_str, commit_sha);
    let cached_pcrs_path = format!("{}/{}-{}.pcrs", cache_dir_str, app_id_str, commit_sha);
    let eif_cache_exists = tokio::fs::metadata(&cached_eif_path).await.is_ok() && !build_config.no_cache;

    let eif_result = if eif_cache_exists {
        tracing::info!("EIF Cache HIT: Using cached EIF for commit {}", commit_sha);

        let eif_data = tokio::fs::read(&cached_eif_path).await.map_err(|e| {
            tracing::error!("Failed to read cached EIF: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read cached EIF: {}", e))
        })?;

        let eif_size_bytes = eif_data.len() as u64;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&eif_data);
        let eif_hash = format!("{:x}", hasher.finalize());

        tracing::info!("Cached EIF loaded: {} bytes, hash: {}", eif_size_bytes, eif_hash);

        types::EIFBuildResult {
            eif_path: cached_eif_path.clone(),
            pcrs_path: cached_pcrs_path.clone(),
            eif_hash,
            eif_size_bytes,
        }
    } else {
        tracing::info!("Building EIF using enclave-builder from Docker image: caution-{}:latest", app_id_str);

        let enclave_source = if !build_config.enclave_sources.is_empty() {
            build_config.enclave_sources[0].clone()
        } else {
            enclave_builder::enclave_source_url(&enclave_builder::build::resolve_enclaveos_commit())
        };
        tracing::info!("Using enclave source: {}", enclave_source);

        let builder = enclave_builder::EnclaveBuilder::new(
            "unused-template",
            "local",
            &enclave_source,
            "unused",
            enclave_builder::FRAMEWORK_SOURCE,
        )
            .map_err(|e| {
                tracing::error!("Failed to create enclave builder: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize enclave builder: {}", e))
            })?
            .with_work_dir(std::path::PathBuf::from(&work_dir))
            .with_no_cache(build_config.no_cache);

        let user_image = enclave_builder::UserImage {
            reference: format!("caution-{}:{}", app_id_str, &commit_sha[..12]),
        };
        tracing::info!("Using Docker image for enclave build: {}", user_image.reference);

        let run_command = build_config.run.clone();
        if let Some(ref cmd) = run_command {
            tracing::info!("Using run command from Procfile: {}", cmd);
        } else {
            tracing::info!("No run command specified, using auto-detection");
        }

        let app_source_urls: Vec<String> = build_config.app_sources.clone();
        tracing::info!("Using {} app source URL(s): {:?}", app_source_urls.len(), app_source_urls);

        let deployment = if let Some(ref binary_path) = build_config.binary {
            tracing::info!("Using static binary extraction mode: {}", binary_path);
            builder
                .build_enclave_auto(
                    &user_image,
                    binary_path,
                    run_command,
                    Some(app_source_urls),
                    Some(req.branch.clone()),
                    Some(commit_sha.clone()),
                    build_config.metadata.clone(),
                    None,
                    &enclave_config.ports,
                    build_config.e2e,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to build enclave: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave build failed: {}", e))
                })?
        } else {
            tracing::info!("Using full filesystem extraction mode (no binary specified)");
            builder
                .build_enclave(
                    &user_image,
                    None,
                    run_command,
                    Some(build_config.app_sources.clone()),
                    Some(req.branch.clone()),
                    Some(commit_sha.clone()),
                    build_config.metadata.clone(),
                    None,
                    &enclave_config.ports,
                    build_config.e2e,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to build enclave: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave build failed: {}", e))
                })?
        };

        tracing::info!(
            "EIF built successfully: path={}, size={} bytes, hash={}",
            deployment.eif.path.display(),
            deployment.eif.size,
            deployment.eif.sha256
        );
        tracing::info!(
            "PCR values: PCR0={}, PCR1={}, PCR2={}",
            deployment.pcrs.pcr0,
            deployment.pcrs.pcr1,
            deployment.pcrs.pcr2
        );

        let built_eif_path = deployment.eif.path.to_string_lossy().to_string();
        let built_pcrs_path = deployment.eif.path.with_extension("pcrs").to_string_lossy().to_string();

        tracing::info!("Caching EIF to: {}", cached_eif_path);
        if let Err(e) = tokio::fs::copy(&built_eif_path, &cached_eif_path).await {
            tracing::warn!("Failed to cache EIF (non-fatal): {:?}", e);
        }
        if let Err(e) = tokio::fs::copy(&built_pcrs_path, &cached_pcrs_path).await {
            tracing::warn!("Failed to cache PCRs (non-fatal): {:?}", e);
        }

        types::EIFBuildResult {
            eif_path: cached_eif_path.clone(),
            pcrs_path: cached_pcrs_path.clone(),
            eif_hash: deployment.eif.sha256,
            eif_size_bytes: deployment.eif.size,
        }
    };

    let eif_path = eif_result.eif_path.clone();
    let eif_hash = eif_result.eif_hash.clone();

    tracing::info!("Storing EIF metadata: path={}, hash={}", eif_path, eif_hash);

    let eif_config = serde_json::json!({
        "eif_path": eif_path,
        "eif_hash": eif_hash,
        "pcrs_path": eif_result.pcrs_path,
        "eif_size_bytes": eif_result.eif_size_bytes,
        "commit_sha": commit_sha,
        "run_command": build_config.run,
        "domain": build_config.domain,
        "memory_mb": enclave_config.memory_mb,
        "cpus": enclave_config.cpus,
        "debug": enclave_config.debug,
        "ports": enclave_config.ports,
        "http_port": enclave_config.http_port,
    });

    let memory_bytes = (enclave_config.memory_mb as u64) * 1024 * 1024;
    if eif_result.eif_size_bytes > memory_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "EIF size ({} MB) exceeds allocated enclave memory ({} MB). Increase memory_mb in Procfile.",
                eif_result.eif_size_bytes / (1024 * 1024),
                enclave_config.memory_mb
            ),
        ));
    }
    if eif_result.eif_size_bytes > memory_bytes * 80 / 100 {
        tracing::warn!(
            "EIF size ({} MB) is more than 80% of allocated memory ({} MB). Consider increasing memory_mb.",
            eif_result.eif_size_bytes / (1024 * 1024),
            enclave_config.memory_mb
        );
    }

    tracing::info!("Deploying Nitro Enclave for resource {} with memory_mb={}, cpu_count={}, debug={}",
                   resource_id, enclave_config.memory_mb, enclave_config.cpus, enclave_config.debug);

    // Check if there's a managed-on-prem credential linked to this resource
    // This takes precedence over the Procfile - if init was called with --config,
    // the credential is already linked to the resource
    let (credentials, managed_onprem_config) = {
        let cred = cloud_credentials::get_credential_by_resource(
            &state.db,
            req.org_id,
            resource_id,
        ).await?;

        if let Some(credential) = cred {
            if credential.managed_on_prem {
                tracing::info!("Managed on-prem credential found for resource {}, using linked credential", resource_id);

                let encryptor = state.encryptor.as_ref().ok_or_else(|| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Encryptor not configured".to_string())
                })?;

                let secrets = cloud_credentials::get_credential_secrets(
                    &state.db,
                    encryptor,
                    req.org_id,
                    credential.id,
                ).await?;

                match secrets {
                    Some(secrets_json) => {
                        let aws_access_key_id = secrets_json["aws_access_key_id"]
                            .as_str()
                            .ok_or_else(|| {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Missing aws_access_key_id in managed on-prem credentials".to_string())
                            })?;
                        let aws_secret_access_key = secrets_json["aws_secret_access_key"]
                            .as_str()
                            .ok_or_else(|| {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Missing aws_secret_access_key in managed on-prem credentials".to_string())
                            })?;

                        // Extract infrastructure config from credential
                        let config = &credential.config;
                        let region = config["aws_region"].as_str().unwrap_or("us-west-2").to_string();

                        let onprem_config = deployment::ManagedOnPremConfig {
                            deployment_id: config["deployment_id"].as_str().unwrap_or("").to_string(),
                            asg_name: config["asg_name"].as_str().unwrap_or("").to_string(),
                            launch_template_name: config["launch_template_name"].as_str().unwrap_or("").to_string(),
                            launch_template_id: config["launch_template_id"].as_str().unwrap_or("").to_string(),
                            vpc_id: config["vpc_id"].as_str().unwrap_or("").to_string(),
                            subnet_ids: config["subnet_ids"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            eif_bucket: config["eif_bucket"].as_str().unwrap_or("").to_string(),
                            instance_profile_name: config["instance_profile_name"].as_str().unwrap_or("").to_string(),
                        };

                        tracing::info!("Using managed on-prem config: deployment_id={}, region={}", onprem_config.deployment_id, region);

                        (
                            Some(deployment::AwsCredentials {
                                access_key_id: aws_access_key_id.to_string(),
                                secret_access_key: aws_secret_access_key.to_string(),
                                region,
                            }),
                            Some(onprem_config),
                        )
                    }
                    None => {
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to decrypt managed on-prem credentials".to_string()));
                    }
                }
            } else {
                // Credential linked but not managed on-prem - fully managed deployment
                tracing::info!("Non-managed-on-prem credential found, using fully managed deployment");
                (None, None)
            }
        } else {
            // No credential linked - fully managed deployment
            tracing::info!("No credential linked to resource {}, using fully managed deployment", resource_id);
            (None, None)
        }
    };

    // Extract region from credentials before moving into nitro_request
    let deployed_region = credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| "us-west-2".to_string());

    let nitro_request = deployment::NitroDeploymentRequest {
        org_id: req.org_id,
        resource_id,
        resource_name: app_name.clone(),
        aws_account_id: aws_account_id.clone(),
        role_arn: role_arn_opt.clone(),
        eif_path: eif_path.clone(),
        memory_mb: enclave_config.memory_mb,
        cpu_count: enclave_config.cpus,
        disk_gb: build_config.disk_gb,
        debug_mode: enclave_config.debug,
        ports: enclave_config.ports.clone(),
        http_port: enclave_config.http_port,
        ssh_keys: build_config.ssh_keys.clone(),
        domain: build_config.domain.clone(),
        credentials,
        managed_onprem: managed_onprem_config,
    };

    let _ = tx.send(Ok(milestone("Uploading and launching..."))).await;

    let deployment_result = match deployment::deploy_nitro_enclave(nitro_request).await {
        Ok(result) => {
            tracing::info!(
                "Nitro Enclave deployed: instance_id={}, public_ip={}",
                result.instance_id,
                result.public_ip
            );
            result
        }
        Err(e) => {
            tracing::error!("Failed to deploy Nitro Enclave: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Nitro deployment failed: {}", e),
            ));
        }
    };

    let mut final_config = eif_config.clone();
    if let Some(instance_type) = &deployment_result.instance_type {
        final_config["instance_type"] = serde_json::json!(instance_type);
    }

    sqlx::query(
        "UPDATE compute_resources
         SET provider_resource_id = $1, state = $2, public_ip = $3, region = $4, configuration = COALESCE(configuration, '{}'::jsonb) || $5::jsonb
         WHERE id = $6 AND organization_id = $7"
    )
    .bind(&deployment_result.instance_id)
    .bind(types::ResourceState::Running)
    .bind(&deployment_result.public_ip)
    .bind(&deployed_region)
    .bind(&final_config)
    .bind(resource_id)
    .bind(req.org_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

    tracing::info!(
        "EIF deployment complete: resource_id={}, instance_id={}, public_ip={}, instance_type={:?}",
        resource_id,
        deployment_result.instance_id,
        deployment_result.public_ip,
        deployment_result.instance_type
    );

    let app_url = if let Some(ref domain) = build_config.domain {
        format!("https://{}", domain)
    } else {
        format!("http://{}", deployment_result.public_ip)
    };
    let attestation_url = format!("{}/attestation", app_url);

    let _ = tx.send(Ok(milestone("Waiting for health check..."))).await;

    tracing::info!("Waiting for attestation endpoint to become healthy...");
    if let Err(e) = wait_for_attestation_health(&deployment_result.public_ip, 120).await {
        tracing::error!("Attestation health check failed: {}", e);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave failed to become healthy: {}", e)));
    }

    tracing::info!(
        "Deployment URLs - App: {}, Attestation: {}",
        app_url,
        attestation_url
    );

    let _ = tx.send(Ok(milestone_done("Deployment successful!"))).await;

    Ok(DeployResponse {
        url: app_url,
        attestation_url,
        resource_id,
        public_ip: deployment_result.public_ip.clone(),
        domain: build_config.domain.clone(),
    })
}

/// Helper: call the internal unsuspend endpoint (used after credit purchase/auto-topup).
async fn call_internal_unsuspend(state: &AppState, org_id: Uuid) -> Result<(), String> {
    let secret = state.internal_service_secret.as_deref().unwrap_or_default();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:8080/internal/org/{}/unsuspend", org_id))
        .header("x-internal-service-secret", secret)
        .send()
        .await
        .map_err(|e| format!("Failed to call unsuspend: {}", e))?;

    if resp.status().is_success() {
        tracing::info!("Unsuspended org {} after credit deposit", org_id);
        Ok(())
    } else {
        Err(format!("Unsuspend returned {}", resp.status()))
    }
}

/// Internal endpoint: suspend only fully-managed resources for an org (credit exhaustion).
/// Unlike suspend_org_resources which suspends ALL resources, this only suspends resources
/// that are NOT managed on-prem — credit exhaustion should not affect BYOC deployments.
async fn suspend_managed_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Suspending fully-managed resources for org {} (credit exhaustion)", org_id);

    let resources: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT cr.id, cr.resource_name FROM compute_resources cr
         WHERE cr.organization_id = $1 AND cr.state = 'running'
           AND NOT EXISTS (
               SELECT 1 FROM cloud_credentials cc
               WHERE cc.resource_id = cr.id AND cc.managed_on_prem = true
           )"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut stopped = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name) in &resources {
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["running"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.stop_instances(&ids).await {
                        tracing::error!("Failed to stop instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Stopped {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No running instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        let _ = sqlx::query("UPDATE compute_resources SET state = 'stopped' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await;
        stopped += 1;
    }

    Ok(Json(serde_json::json!({
        "stopped": stopped,
        "total": resources.len(),
        "errors": errors,
    })))
}

// -- Auto top-up API endpoints --

#[derive(Deserialize)]
struct AutoTopupConfig {
    enabled: bool,
    amount_dollars: i32,
}

async fn get_auto_topup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT auto_topup_enabled, auto_topup_amount_dollars FROM billing_config WHERE user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let (enabled, amount) = match row {
        Some(r) => (
            r.get::<Option<bool>, _>("auto_topup_enabled").unwrap_or(false),
            r.get::<Option<i32>, _>("auto_topup_amount_dollars").unwrap_or(0),
        ),
        None => (false, 0),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "amount_dollars": amount,
    })))
}

async fn put_auto_topup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<AutoTopupConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if req.amount_dollars < 0 || req.amount_dollars > 10_000 {
        return Err((StatusCode::BAD_REQUEST,
            "Auto top-up amount must be between $0 and $10,000".to_string()));
    }
    if req.enabled && req.amount_dollars < 10 {
        return Err((StatusCode::BAD_REQUEST,
            "Auto top-up target must be at least $10".to_string()));
    }

    // Verify user has an active payment method (required for auto-topup)
    if req.enabled {
        let org_id = get_user_primary_org(&state.db, auth.user_id)
            .await
            .map_err(|e| (e, "Failed to get organization".to_string()))?;

        let payment_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM payment_methods WHERE organization_id = $1 AND is_active = true"
        )
        .bind(org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        if payment_count == 0 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "An active payment method is required to enable auto top-up".to_string()));
        }
    }

    sqlx::query(
        "INSERT INTO billing_config (user_id, auto_topup_enabled, auto_topup_amount_dollars)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET
             auto_topup_enabled = $2,
             auto_topup_amount_dollars = $3"
    )
    .bind(auth.user_id)
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

/// Internal endpoint: suspend all running resources for an org (stop EC2 instances).
/// Called by the metering service during dunning enforcement.
async fn suspend_org_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Suspending all running resources for org {}", org_id);

    let resources: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, resource_name FROM compute_resources
         WHERE organization_id = $1 AND state = 'running'"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut stopped = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name) in &resources {
        // Get AWS credentials for this resource
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["running"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.stop_instances(&ids).await {
                        tracing::error!("Failed to stop instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Stopped {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No running instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        // Mark resource as stopped in DB regardless
        let _ = sqlx::query("UPDATE compute_resources SET state = 'stopped' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await;
        stopped += 1;
    }

    // Mark org as suspended
    let _ = sqlx::query(
        "UPDATE organizations SET dunning_stage = 'suspended' WHERE id = $1"
    )
    .bind(org_id)
    .execute(&state.db)
    .await;

    Ok(Json(serde_json::json!({
        "stopped": stopped,
        "total": resources.len(),
        "errors": errors,
    })))
}

/// Internal endpoint: unsuspend org — restart stopped resources and clear dunning state.
/// Called when payment is resolved (credit deposit, new payment method, etc).
async fn unsuspend_org_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Unsuspending resources for org {}", org_id);

    let resources: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, resource_name FROM compute_resources
         WHERE organization_id = $1 AND state = 'stopped'"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut started = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name) in &resources {
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["stopped"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.start_instances(&ids).await {
                        tracing::error!("Failed to start instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Started {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No stopped instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        let _ = sqlx::query("UPDATE compute_resources SET state = 'running' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await;
        started += 1;
    }

    // Clear dunning state
    let _ = sqlx::query(
        "UPDATE organizations SET payment_failed_at = NULL, dunning_stage = 'none' WHERE id = $1"
    )
    .bind(org_id)
    .execute(&state.db)
    .await;

    Ok(Json(serde_json::json!({
        "started": started,
        "total": resources.len(),
        "errors": errors,
    })))
}

/// Helper: get AWS credentials for a resource (managed on-prem or platform default).
async fn get_aws_credentials_for_resource(
    state: &AppState,
    org_id: Uuid,
    resource_id: Uuid,
) -> Option<deployment::AwsCredentials> {
    // Check for managed on-prem credentials first
    if let Some(encryptor) = state.encryptor.as_ref() {
        if let Ok(Some(credential)) = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id).await {
            if credential.managed_on_prem {
                if let Ok(Some(secrets)) = cloud_credentials::get_credential_secrets(&state.db, encryptor, org_id, credential.id).await {
                    let region = credential.config["aws_region"].as_str()
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("AWS_REGION").ok())
                        .unwrap_or_else(|| "us-west-2".to_string());
                    return Some(deployment::AwsCredentials {
                        access_key_id: secrets["aws_access_key_id"].as_str().unwrap_or("").to_string(),
                        secret_access_key: secrets["aws_secret_access_key"].as_str().unwrap_or("").to_string(),
                        region,
                    });
                }
            }
        }
    }

    // Fall back to platform credentials from env
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    Some(deployment::AwsCredentials {
        access_key_id,
        secret_access_key,
        region,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    if let Err(e) = provisioning::validate_setup() {
        tracing::warn!("Provisioning validation failed: {:?}", e);
        tracing::warn!("AWS child account provisioning will not be available");
    }
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let git_hostname = std::env::var("GIT_HOSTNAME")
        .unwrap_or_else(|_| "alpha.caution.co".to_string());

    let git_ssh_port: Option<u16> = std::env::var("SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok());

    let data_dir = std::env::var("CAUTION_DATA_DIR")
        .unwrap_or_else(|_| "/var/cache/caution".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    info!("Connected to database");

    let encryptor = match encryption::Encryptor::from_env() {
        Ok(e) => {
            info!("Encryption enabled for cloud credentials");
            Some(Arc::new(e))
        }
        Err(e) => {
            tracing::warn!("Encryption not configured: {}. Cloud credentials feature disabled.", e);
            None
        }
    };

    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if internal_service_secret.is_some() {
        info!("Internal service authentication enabled");
    } else {
        tracing::warn!("INTERNAL_SERVICE_SECRET not set - internal service authentication disabled");
    }

    // Paddle configuration
    let paddle_client_token = std::env::var("PADDLE_CLIENT_TOKEN").ok();
    let paddle_setup_price_id = std::env::var("PADDLE_SETUP_PRICE_ID").ok();
    if paddle_client_token.is_some() {
        info!("Paddle billing integration enabled");
    }
    if paddle_setup_price_id.is_none() {
        tracing::warn!("PADDLE_SETUP_PRICE_ID not set - checkout will not have items");
    }

    let paddle_credits_price_ids = [
        std::env::var("PADDLE_CREDITS_PRICE_ID_1000").ok(),
        std::env::var("PADDLE_CREDITS_PRICE_ID_5000").ok(),
        std::env::var("PADDLE_CREDITS_PRICE_ID_25000").ok(),
    ];

    let paddle_api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
    let paddle_api_key = std::env::var("PADDLE_API_KEY").ok();

    if paddle_api_key.is_some() && paddle_api_url.is_empty() {
        return Err("PADDLE_API_KEY is set but PADDLE_API_URL is not — set PADDLE_API_URL to the Paddle API base URL (e.g. https://sandbox-api.paddle.com or https://api.paddle.com)".into());
    }

    let pricing = PricingConfig::load();

    let state = Arc::new(AppState {
        db: pool,
        git_hostname,
        git_ssh_port,
        data_dir,
        encryptor,
        internal_service_secret,
        paddle_client_token,
        paddle_setup_price_id,
        paddle_credits_price_ids,
        paddle_api_url,
        paddle_api_key,
        pricing,
    });

    let onboarding_routes = Router::new()
        .route("/user/status", get(onboarding::get_user_status))
        .route("/onboarding/send-verification", post(onboarding::send_verification_email))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let resource_routes = Router::new()
        .route("/users/me", get(get_current_user))
        .route("/users/me", patch(update_current_user))
        .route("/users/me", delete(delete_current_user))
        .route("/organizations", get(list_organizations))
        .route("/organizations", post(create_organization))
        .route("/organizations/{id}", get(get_organization))
        .route("/organizations/{id}", patch(update_organization))
        .route("/organizations/{id}", delete(delete_organization))
        .route("/organizations/{id}/settings", get(get_org_settings))
        .route("/organizations/{id}/settings", patch(update_org_settings))
        .route("/organizations/{id}/members", get(list_members))
        .route("/organizations/{id}/members", post(add_member))
        .route("/organizations/{id}/members/{user_id}", patch(update_member))
        .route("/organizations/{id}/members/{user_id}", delete(remove_member))
        .route("/resources", post(create_resource))
        .route("/resources", get(list_resources))
        .route("/resources/{id}", get(get_resource))
        .route("/resources/{id}", patch(rename_resource))
        .route("/resources/{id}", delete(delete_resource))
        .route("/resources/{id}/attestation", post(proxy_attestation))
        .route("/resources/managed-onprem", post(create_managed_onprem_resource))
        .route("/deploy", post(deploy_handler))
        .route("/credentials", get(list_cloud_credentials))
        .route("/credentials", post(create_cloud_credential))
        .route("/credentials/{id}", get(get_cloud_credential))
        .route("/credentials/{id}", delete(delete_cloud_credential))
        .route("/credentials/{id}/default", post(set_default_cloud_credential))
        .route("/quorum-bundles", get(list_quorum_bundles))
        .route("/quorum-bundles", post(create_quorum_bundle))
        .route("/quorum-bundles/{id}", get(get_quorum_bundle))
        .route("/quorum-bundles/{id}", patch(update_quorum_bundle))
        .route("/quorum-bundles/{id}", delete(delete_quorum_bundle))
        .route("/secrets-bundles", get(list_secrets_bundles))
        .route("/secrets-bundles", post(create_secrets_bundle))
        .route("/secrets-bundles/{id}", get(get_secrets_bundle))
        .route("/secrets-bundles/{id}", patch(update_secrets_bundle))
        .route("/secrets-bundles/{id}", delete(delete_secrets_bundle))
        .route("/billing/usage", get(get_billing_usage))
        .route("/billing/invoices", get(get_billing_invoices))
        .route("/billing/payment-methods", get(get_payment_methods))
        .route("/billing/payment-methods/{id}", delete(delete_payment_method))
        .route("/billing/payment-methods/{id}/set-primary", post(set_primary_payment_method))
        .route("/billing/paddle/client-token", get(get_paddle_client_token))
        .route("/billing/paddle/transaction-completed", post(paddle_transaction_completed))
        .route("/billing/credits/balance", get(get_credit_balance))
        .route("/billing/credits/packages", get(get_credit_packages))
        .route("/billing/credits/purchase", post(purchase_credits))
        .route("/billing/credits/ledger", get(get_credit_ledger))
        .route("/billing/credits/redeem", post(redeem_credit_code))
        .route("/billing/auto-topup", get(get_auto_topup))
        .route("/billing/auto-topup", put(put_auto_topup))
        .route("/billing/subscription/tiers", get(get_subscription_tiers))
        .route("/billing/subscription", get(get_subscription))
        .route("/billing/subscription/subscribe", post(subscribe))
        .route("/billing/subscription/change-tier", post(change_subscription_tier))
        .route("/billing/subscription/add-capacity", post(add_subscription_capacity))
        .route("/billing/subscription/cancel", post(cancel_subscription))
        .route("/billing/subscription/reactivate", post(reactivate_subscription))
        .layer(middleware::from_fn_with_state(state.clone(), onboarding_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let internal_routes = Router::new()
        .route("/internal/org/{org_id}/suspend", post(suspend_org_resources))
        .route("/internal/org/{org_id}/suspend-managed", post(suspend_managed_resources))
        .route("/internal/org/{org_id}/unsuspend", post(unsuspend_org_resources))
        .layer(middleware::from_fn_with_state(state.clone(), internal_auth_middleware));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/onboarding/verify", get(onboarding::verify_email));

    let app = Router::new()
        .merge(onboarding_routes)
        .merge(resource_routes)
        .merge(internal_routes)
        .merge(public_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await?;
    
    info!("API server listening on 0.0.0.0:8080");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )
    .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }
}

// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use axum::{
    middleware,
    routing::{get, post, delete},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    services::ServeDir,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use russh_keys::key::KeyPair;

mod config;
mod db;
mod handlers;
mod auth_middleware;
mod proxy;
mod types;
mod ssh_server;
mod validation;
mod rate_limit;

use config::Config;
use types::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env().context("Failed to load configuration")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("Failed to connect to database")?;

    tracing::info!("Database connected");

    let origins: Vec<Url> = config
        .rp_origins
        .iter()
        .filter_map(|s| Url::parse(s).ok())
        .collect();

    if origins.is_empty() {
        anyhow::bail!("No valid RP origins configured");
    }

    let rp_id = &config.rp_id;
    let mut builder = WebauthnBuilder::new(rp_id, &origins[0])
        .context("Failed to create WebAuthn builder")?;

    for origin in origins.iter().skip(1) {
        builder = builder.append_allowed_origin(origin);
    }

    let webauthn = builder
        .rp_name(&config.rp_display_name)
        .build()
        .context("Failed to build WebAuthn")?;

    tracing::info!("WebAuthn configured:");
    tracing::info!("  RP ID: {}", config.rp_id);
    tracing::info!("  RP Display Name: {}", config.rp_display_name);
    tracing::info!("  RP Origins: {:?}", config.rp_origins);

    let host_key = load_or_generate_host_key(&config.ssh_host_key_path)
        .context("Failed to load SSH host key")?;

    let state = AppState {
        db: pool.clone(),
        webauthn,
        api_service_url: config.api_service_url.clone(),
        reg_states: Arc::new(RwLock::new(HashMap::new())),
        auth_states: Arc::new(RwLock::new(HashMap::new())),
        sign_challenges: Arc::new(RwLock::new(HashMap::new())),
        session_timeout_hours: config.session_timeout_hours,
    };

    let rate_limiter = rate_limit::RateLimiter::new(100, 60);

    let rate_limiter_cleanup = rate_limiter.clone();
    tokio::spawn(async move {
        rate_limiter_cleanup.cleanup_task().await;
    });

    let cors = CorsLayer::new()
        .allow_origin(
            config
                .rp_origins
                .iter()
                .filter_map(|origin| origin.parse().ok())
                .collect::<Vec<_>>(),
        )
        .allow_credentials(true)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            "Content-Type".parse().unwrap(),
            "X-Session-ID".parse().unwrap(),
            "Authorization".parse().unwrap(),
            "X-Fido2-Challenge-Id".parse().unwrap(),
            "X-Fido2-Response".parse().unwrap(),
        ]);

    let auth_routes = Router::new()
        .route("/auth/register/begin", post(handlers::begin_register_handler))
        .route("/auth/register/finish", post(handlers::finish_register_handler))
        .route("/auth/login/begin", post(handlers::begin_login_handler))
        .route("/auth/login/finish", post(handlers::finish_login_handler))
        .route("/auth/sign-request", post(handlers::begin_sign_request_handler))
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/health", get(handlers::health_handler))
        .merge(auth_routes)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(cors.clone());

    let protected = Router::new()
        .route("/ssh-keys", post(handlers::add_ssh_key_handler))
        .route("/ssh-keys", get(handlers::list_ssh_keys_handler))
        .route("/ssh-keys/{fingerprint}", delete(handlers::delete_ssh_key_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware::fido2_auth_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware::fido2_sign_middleware))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let public_api_proxy = Router::new()
        .route("/onboarding/verify", get(proxy::proxy_handler))
        .route("/config/stripe-key", get(proxy::proxy_handler))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let api_proxy = Router::new()
        .fallback(proxy::proxy_handler)
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware::fido2_auth_middleware))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let frontend_dir = std::env::var("FRONTEND_DIR")
        .unwrap_or_else(|_| "/app/frontend".to_string());

    let frontend_service = ServeDir::new(&frontend_dir)
        .append_index_html_on_directories(true);

    let app = app
        .merge(protected)
        .nest("/api", public_api_proxy.merge(api_proxy))
        .fallback_service(frontend_service)
        .layer(cors);

    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match db::cleanup_expired_sessions(&cleanup_pool).await {
                Ok(count) if count > 0 => {
                    tracing::info!("Cleaned up {} expired sessions", count);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Failed to cleanup expired sessions: {:?}", e);
                }
            }
        }
    });

    let ssh_pool = pool.clone();
    let ssh_api_url = config.api_service_url.clone();
    let ssh_data_dir = config.data_dir.clone();
    let ssh_bind_addr = format!("0.0.0.0:{}", config.ssh_port);
    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if internal_service_secret.is_some() {
        tracing::info!("Internal service authentication enabled");
    } else {
        tracing::warn!("INTERNAL_SERVICE_SECRET not set - internal service authentication disabled");
    }
    tokio::spawn(async move {
        if let Err(e) = ssh_server::run_ssh_server(ssh_pool, ssh_api_url, ssh_data_dir, internal_service_secret, host_key, &ssh_bind_addr).await {
            tracing::error!("SSH server error: {:?}", e);
        }
    });

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    tracing::info!("Gateway listening on {}", addr);
    tracing::info!("SSH server listening on port {}", config.ssh_port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .context("Server error")?;

    Ok(())
}

fn load_or_generate_host_key(path: &str) -> Result<KeyPair> {
    use std::fs;
    use std::path::Path;

    let key_path = Path::new(path);

    if key_path.exists() {
        let key_data = fs::read(key_path)
            .with_context(|| format!("Failed to read SSH host key from {}", path))?;

        let key = russh_keys::decode_secret_key(&String::from_utf8_lossy(&key_data), None)
            .context("Failed to decode SSH host key")?;

        tracing::debug!("Loaded SSH host key");
        Ok(key)
    } else {
        tracing::info!("Generating new SSH host key");

        let key = KeyPair::generate_ed25519()
            .context("Failed to generate Ed25519 key")?;

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let mut key_data = Vec::new();
        russh_keys::encode_pkcs8_pem(&key, &mut key_data)
            .context("Failed to encode SSH host key")?;
        fs::write(key_path, &key_data)
            .with_context(|| format!("Failed to write SSH host key to {}", path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms)?;
        }

        tracing::info!("SSH host key generated");
        Ok(key)
    }
}

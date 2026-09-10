// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;

mod auth_middleware;
mod config;
mod csrf;
mod db;
mod decoy;
mod handlers;
mod pgp;
mod rate_limit;
mod request_id;
mod security_headers;
mod ssh_server;
mod types;
mod validation;

use config::Config;
use types::AppState;

#[derive(Debug, thiserror::Error, CtxError)]
enum MainError {
    #[error("failed to load configuration [{location}]")]
    Config {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to connect to database [{location}]")]
    DatabaseConnection {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no valid RP origins configured [{location}]")]
    NoValidOrigins {
        #[location]
        location: Location,
    },

    #[error("non-localhost RP origin must use HTTPS in production: {origin} [{location}]")]
    InsecureOrigin {
        origin: String,

        #[location]
        location: Location,
    },

    #[error("failed to create WebAuthn builder [{location}]")]
    WebauthnBuilder {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build WebAuthn [{location}]")]
    WebauthnBuild {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to load SSH host key [{location}]")]
    HostKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build HTTP client [{location}]")]
    HttpClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to bind to address {addr} [{location}]")]
    BindAddress {
        #[context(borrow = str)]
        addr: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("server error [{location}]")]
    Server {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
enum LoadHostKeyError {
    #[error("failed to read SSH host key from {path} [{location}]")]
    ReadKeyFile {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to decode SSH host key [{location}]")]
    DecodeKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to generate Ed25519 key [{location}]")]
    GenerateKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create directory {parent} [{location}]")]
    CreateDirectory {
        #[context(borrow = std::path::Path)]
        parent: std::path::PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to encode SSH host key [{location}]")]
    EncodeKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to write SSH host key to {path} [{location}]")]
    WriteKeyFile {
        #[context(borrow = str)]
        path: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to set permissions on SSH host key [{location}]")]
    SetPermissions {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read SSH host key metadata [{location}]")]
    ReadMetadata {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    use MainErrorCtx as Ctx;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gateway=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(feature = "e2e-testing-unsafe")]
    {
        let env = std::env::var("ENVIRONMENT").unwrap_or_default();
        if env == "production" {
            eprintln!("FATAL: e2e-testing-unsafe feature is enabled in a production build. Refusing to start.");
            std::process::exit(1);
        }
        tracing::warn!("e2e-testing-unsafe feature is enabled — /auth/e2e-login endpoint is active. Do NOT use in production.");
    }

    let config = Config::from_env().with_context(Ctx::config())?;

    let max_db_connections: u32 = std::env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    let pool = PgPoolOptions::new()
        .max_connections(max_db_connections)
        .connect(&config.database_url)
        .await
        .with_context(Ctx::database_connection())?;

    tracing::info!("Database connected");

    let origins: Vec<Url> = config
        .rp_origins
        .iter()
        .filter_map(|s| Url::parse(s).ok())
        .collect();

    if origins.is_empty() {
        return Err(MainError::NoValidOrigins {
            location: std::panic::Location::caller(),
        });
    }

    let is_production = std::env::var("ENVIRONMENT")
        .map(|e| e == "production")
        .unwrap_or(false);
    if is_production {
        for origin in &origins {
            if origin.scheme() == "http" && origin.host_str() != Some("localhost") {
                return Err(MainError::InsecureOrigin {
                    origin: origin.to_string(),
                    location: std::panic::Location::caller(),
                });
            }
        }
    }

    let rp_id = &config.rp_id;
    let mut builder =
        WebauthnBuilder::new(rp_id, &origins[0]).with_context(Ctx::webauthn_builder())?;

    for origin in origins.iter().skip(1) {
        builder = builder.append_allowed_origin(origin);
    }

    let webauthn = builder
        .rp_name(&config.rp_display_name)
        .build()
        .with_context(Ctx::webauthn_build())?;

    // Fail fast if the login-begin decoy timing-equalization fixtures ever
    // stop deserializing (e.g. a future webauthn-rs upgrade changing
    // `SecurityKey`'s serde shape), rather than silently degrading the
    // enumeration-defense timing fix at request time.
    handlers::validate_decoy_timing_fixtures();

    tracing::info!("WebAuthn configured:");
    tracing::info!("  RP ID: {}", config.rp_id);
    tracing::info!("  RP Display Name: {}", config.rp_display_name);
    tracing::info!("  RP Origins: {:?}", config.rp_origins);

    let host_key =
        load_or_generate_host_key(&config.ssh_host_key_path).with_context(Ctx::host_key())?;

    // Kill-switch for legacy credential-broadcast login (see AppState::login_allow_broadcast
    // doc comment). Read once at startup — toggling requires an env var change + restart.
    let login_allow_broadcast = std::env::var("LOGIN_ALLOW_BROADCAST")
        .ok()
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    tracing::info!("login_allow_broadcast = {}", login_allow_broadcast);

    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if internal_service_secret.is_some() {
        tracing::info!("Internal service authentication enabled");
    } else {
        tracing::warn!(
            "INTERNAL_SERVICE_SECRET not set - internal service authentication disabled"
        );
    }

    // Three independent in-memory rate limiters (see doc comments in
    // `rate_limit.rs` for the single-gateway-replica assumption):
    //  - `rate_limiter`: blanket per-IP budget over all /auth/* routes.
    //  - `scoped_begin_limiter`: tighter per-IP budget on username-scoped
    //    begin requests only (409/handlers.rs), hard 429 on exceed.
    //  - `username_begin_limiter`: per-username budget on scoped begin
    //    requests; exceeding it forces a decoy response instead of a 429.
    let rate_limiter = rate_limit::RateLimiter::new(
        rate_limit::GLOBAL_MAX_REQUESTS,
        rate_limit::GLOBAL_WINDOW_SECS,
    );
    let scoped_begin_limiter = rate_limit::RateLimiter::new(
        rate_limit::SCOPED_BEGIN_MAX_REQUESTS,
        rate_limit::SCOPED_BEGIN_WINDOW_SECS,
    );
    let username_begin_limiter = rate_limit::RateLimiter::new(
        rate_limit::USERNAME_BEGIN_MAX_REQUESTS,
        rate_limit::USERNAME_BEGIN_WINDOW_SECS,
    );

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(Ctx::http_client())?;

    let state = AppState {
        db: pool.clone(),
        webauthn,
        relying_party_id: config.rp_id.clone(),
        api_service_url: config.api_service_url.clone(),
        metering_service_url: config.metering_service_url.clone(),
        // Disable redirect-following on the proxy client: proxied API requests
        // carry X-Internal-Service-Secret, and reqwest preserves custom headers
        // across redirects. A backend 3xx (attacker-influenced or not) would
        // otherwise leak the internal secret/body to the redirect target.
        // Backend 3xx responses are relayed to the caller instead.
        http_client,
        reg_states: Arc::new(RwLock::new(HashMap::new())),
        passkey_reg_states: Arc::new(RwLock::new(HashMap::new())),
        auth_states: Arc::new(RwLock::new(HashMap::new())),
        sign_challenges: Arc::new(RwLock::new(HashMap::new())),
        session_timeout_hours: config.session_timeout_hours,
        internal_service_secret: internal_service_secret.clone(),
        csrf_secret: config.csrf_secret.clone(),
        login_allow_broadcast,
        scoped_begin_limiter: scoped_begin_limiter.clone(),
        username_begin_limiter: username_begin_limiter.clone(),
    };

    let rate_limiter_cleanup = rate_limiter.clone();
    tokio::spawn(async move {
        rate_limiter_cleanup.cleanup_task().await;
    });
    tokio::spawn(async move {
        scoped_begin_limiter.cleanup_task().await;
    });
    tokio::spawn(async move {
        username_begin_limiter.cleanup_task().await;
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
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            "Content-Type".parse().unwrap(),
            "X-Session-ID".parse().unwrap(),
            "X-CSRF-Token".parse().unwrap(),
            "Authorization".parse().unwrap(),
            "X-Fido2-Challenge-Id".parse().unwrap(),
            "X-Fido2-Response".parse().unwrap(),
        ]);

    let auth_routes = Router::new()
        .route(
            "/auth/register/begin",
            post(handlers::begin_register_handler),
        )
        .route(
            "/auth/register/finish",
            post(handlers::finish_register_handler),
        )
        .route("/auth/invite", get(handlers::invite_preview_handler))
        .route(
            "/auth/invite/register/begin",
            post(handlers::begin_invite_register_handler),
        )
        .route(
            "/auth/invite/register/finish",
            post(handlers::finish_register_handler),
        )
        .route("/auth/login/begin", post(handlers::begin_login_handler))
        .route("/auth/login/finish", post(handlers::finish_login_handler))
        .route("/auth/logout", post(handlers::logout_handler))
        .route(
            "/auth/qr-login/begin",
            post(handlers::qr_login_begin_handler),
        )
        .route(
            "/auth/qr-login/status",
            get(handlers::qr_login_status_handler),
        )
        .route(
            "/auth/qr-login/authenticate",
            post(handlers::qr_login_authenticate_handler),
        )
        .route(
            "/auth/qr-login/authenticate/finish",
            post(handlers::qr_login_authenticate_finish_handler),
        )
        .route(
            "/auth/sign-request",
            post(handlers::begin_sign_request_handler),
        )
        .route("/auth/qr-sign/begin", post(handlers::qr_sign_begin_handler))
        .route(
            "/auth/qr-sign/status",
            get(handlers::qr_sign_status_handler),
        )
        .route(
            "/auth/qr-sign/authenticate",
            post(handlers::qr_sign_authenticate_handler),
        )
        .route(
            "/auth/qr-sign/authenticate/finish",
            post(handlers::qr_sign_authenticate_finish_handler),
        )
        // CSRF posture: these routes have no session cookie or CSRF token by
        // design. The WebAuthn registration ceremony itself enforces origin
        // binding (rpId must match page origin) and user verification, so a
        // cross-site attacker cannot forge a ceremony even if they can POST here.
        .route(
            "/auth/reset/begin",
            post(handlers::reset_webauthn::begin_reset_register_handler),
        )
        .route(
            "/auth/reset/finish",
            post(handlers::reset_webauthn::finish_reset_register_handler),
        );

    #[cfg(feature = "e2e-testing-unsafe")]
    {
        tracing::warn!("E2E test mode enabled - /auth/e2e-login endpoint is active");
        auth_routes = auth_routes.route("/auth/e2e-login", post(handlers::e2e_login_handler));
    }

    let auth_routes = auth_routes
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
        .route("/passkeys", get(handlers::list_passkeys_handler))
        .route(
            "/passkeys/register/begin",
            post(handlers::begin_add_passkey_handler),
        )
        .route(
            "/passkeys/register/finish",
            post(handlers::finish_add_passkey_handler),
        )
        .route("/passkeys/{id}", delete(handlers::delete_passkey_handler))
        .route("/ssh-keys", post(handlers::add_ssh_key_handler))
        .route("/ssh-keys", get(handlers::list_ssh_keys_handler))
        .route(
            "/ssh-keys/{fingerprint}",
            delete(handlers::delete_ssh_key_handler),
        )
        .route("/user/username", get(handlers::get_username_status_handler))
        .route("/user/username", post(handlers::claim_username_handler))
        .route("/pgp-keys", post(handlers::add_pgp_key_handler))
        .route("/pgp-keys", get(handlers::list_pgp_keys_handler))
        .route("/pgp-keys/{id}", delete(handlers::remove_pgp_key_handler))
        // Added before (so innermost relative to) fido2_auth_middleware, so
        // it runs AFTER auth has resolved AuthenticatedUserId — order of
        // execution for an incoming request is sign -> auth -> gate -> handler.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::username_claim_gate_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::fido2_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::fido2_sign_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let public_api_proxy = Router::new()
        .route("/onboarding/verify", get(handlers::proxy_handler))
        .route("/config/stripe-key", get(handlers::proxy_handler))
        .route("/legal/active-documents", get(handlers::proxy_handler))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let api_proxy = Router::new()
        .fallback(handlers::proxy_handler)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::username_claim_gate_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::fido2_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::fido2_sign_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    let frontend_dir =
        std::env::var("FRONTEND_DIR").unwrap_or_else(|_| "/app/frontend".to_string());

    let frontend_service = ServeDir::new(&frontend_dir).append_index_html_on_directories(true);
    let frontend_routes =
        handlers::frontend::build_frontend_routes(std::path::Path::new(&frontend_dir));

    // Webhook proxy to metering service (no auth required — Paddle verifies via signature)
    let webhook_proxy = Router::new()
        .route("/webhooks/paddle", post(handlers::metering_proxy_handler))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state.clone())
        .layer(cors.clone());

    // Public, unauthenticated, root-level (must NOT be nested under /api): the
    // platform's current enclave build inputs, proxied to the API's same path.
    let well_known_proxy = Router::new()
        .route(
            "/.well-known/caution/build-inputs",
            get(handlers::proxy_handler),
        )
        .with_state(state.clone())
        .layer(cors.clone());

    let app = app
        .merge(protected)
        .merge(webhook_proxy)
        .merge(well_known_proxy)
        .nest("/api", public_api_proxy.merge(api_proxy))
        .merge(frontend_routes)
        .fallback_service(frontend_service)
        .layer(cors)
        .layer(middleware::from_fn(request_id::request_id_middleware))
        .layer(middleware::from_fn(
            security_headers::security_headers_middleware,
        ));

    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            db::run_cleanups(&cleanup_pool).await;
        }
    });

    // Cleanup expired in-memory challenge states (registration, authentication, sign challenges)
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = time::OffsetDateTime::now_utc();

            // Clean up expired registration states
            {
                let mut reg_states = cleanup_state.reg_states.write().await;
                let before_count = reg_states.len();
                reg_states.retain(|_, pending| pending.expires_at > now);
                let removed = before_count - reg_states.len();
                if removed > 0 {
                    tracing::debug!("Cleaned up {} expired registration challenges", removed);
                }
            }

            // Clean up expired passkey registration states
            {
                let mut reg_states = cleanup_state.passkey_reg_states.write().await;
                let before_count = reg_states.len();
                reg_states.retain(|_, pending| pending.expires_at > now);
                let removed = before_count - reg_states.len();
                if removed > 0 {
                    tracing::debug!(
                        "Cleaned up {} expired passkey registration challenges",
                        removed
                    );
                }
            }

            // Clean up expired authentication states
            {
                let mut auth_states = cleanup_state.auth_states.write().await;
                let before_count = auth_states.len();
                auth_states.retain(|_, pending| pending.expires_at > now);
                let removed = before_count - auth_states.len();
                if removed > 0 {
                    tracing::debug!("Cleaned up {} expired authentication challenges", removed);
                }
            }

            // Clean up expired sign challenges
            {
                let mut sign_challenges = cleanup_state.sign_challenges.write().await;
                let before_count = sign_challenges.len();
                sign_challenges.retain(|_, pending| pending.expires_at > now);
                let removed = before_count - sign_challenges.len();
                if removed > 0 {
                    tracing::debug!("Cleaned up {} expired sign challenges", removed);
                }
            }
        }
    });

    let ssh_pool = pool.clone();
    let ssh_api_url = config.api_service_url.clone();
    let ssh_data_dir = config.data_dir.clone();
    let ssh_bind_addr = format!("0.0.0.0:{}", config.ssh_port);
    let ssh_internal_service_secret = internal_service_secret.clone();
    tokio::spawn(async move {
        if let Err(e) = ssh_server::run_ssh_server(
            ssh_pool,
            ssh_api_url,
            ssh_data_dir,
            ssh_internal_service_secret,
            host_key,
            &ssh_bind_addr,
        )
        .await
        {
            tracing::error!("SSH server error: {:?}", e);
        }
    });

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(Ctx::bind_address(&addr))?;

    tracing::info!("Gateway listening on {}", addr);
    tracing::info!("SSH server listening on port {}", config.ssh_port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .with_context(Ctx::server())?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }
}

fn load_or_generate_host_key(path: &str) -> Result<PrivateKey, LoadHostKeyError> {
    use std::fs;
    use std::path::Path;
    use LoadHostKeyErrorCtx as Ctx;

    let key_path = Path::new(path);

    if key_path.exists() {
        let key_str = fs::read_to_string(key_path).with_context(Ctx::read_key_file(path))?;

        let key = russh::keys::decode_secret_key(&key_str, None).with_context(Ctx::decode_key())?;

        tracing::debug!("Loaded SSH host key");
        Ok(key)
    } else {
        tracing::info!("Generating new SSH host key");

        let key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519)
            .with_context(Ctx::generate_key())?;

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).with_context(Ctx::create_directory(parent))?;
        }

        let key_pem = key
            .to_openssh(LineEnding::LF)
            .with_context(Ctx::encode_key())?;
        fs::write(key_path, key_pem.as_bytes()).with_context(Ctx::write_key_file(path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)
                .with_context(Ctx::read_metadata())?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms).with_context(Ctx::set_permissions())?;
        }

        tracing::info!("SSH host key generated");
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::load_or_generate_host_key;
    use russh::keys::{Algorithm, HashAlg};

    #[test]
    fn generates_ed25519_host_key_and_persists_it() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("nested").join("ssh_host_key");
        let path = key_path.to_str().unwrap();

        // First call generates and writes the key.
        let generated = load_or_generate_host_key(path).unwrap();
        assert_eq!(generated.algorithm(), Algorithm::Ed25519);
        assert!(key_path.exists(), "host key file should be written");

        // The on-disk key must be valid OpenSSH PEM (re-decodable).
        let on_disk = std::fs::read_to_string(&key_path).unwrap();
        assert!(on_disk.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "host key must be private (0600)");
        }

        // Second call loads the existing key unchanged (same fingerprint).
        let loaded = load_or_generate_host_key(path).unwrap();
        assert_eq!(
            generated.fingerprint(HashAlg::Sha256),
            loaded.fingerprint(HashAlg::Sha256),
            "loaded key should match the generated key"
        );
    }
}

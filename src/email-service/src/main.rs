// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use lettre::{
    message::{header::ContentType, Message},
    transport::smtp::{authentication::Credentials, response::Response as SmtpResponse},
    SmtpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("Application error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[derive(Clone)]
struct AppState {
    smtp_transport: Option<Arc<SmtpTransport>>,
    from_email: String,
    from_name: String,
    base_url: String,
    test_mode: bool,
}

#[derive(Debug, Deserialize)]
struct SendVerificationRequest {
    email: String,
    token: String,
    user_id: Uuid,
}

#[derive(Debug, Serialize)]
struct SendVerificationResponse {
    success: bool,
    message: String,
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "email" }))
}

async fn send_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<SendVerificationRequest>,
) -> Result<Json<SendVerificationResponse>, AppError> {
    info!("Sending verification email to: {}", req.email);

    let verification_url = format!("{}/api/onboarding/verify?token={}", state.base_url, req.token);

    if state.test_mode {
        info!("");
        info!("========================================");
        info!("EMAIL TEST MODE - VERIFICATION LINK");
        info!("========================================");
        info!("To: {}", req.email);
        info!("User ID: {}", req.user_id);
        info!("");
        info!("Verification URL:");
        info!("  {}", verification_url);
        info!("");
        info!("Copy the URL above to verify the email");
        info!("========================================");
        info!("");

        return Ok(Json(SendVerificationResponse {
            success: true,
            message: format!("TEST MODE: Verification link logged (not sent to {})", req.email),
        }));
    }

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #2c3e50; margin-top: 0;">Welcome to Caution!</h1>

        <p>Thank you for registering. To complete your account setup, please verify your email address.</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #3498db; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Verify Email Address
            </a>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="{}" style="color: #3498db; word-break: break-all;">{}</a>
        </p>

        <p style="color: #7f8c8d; font-size: 14px; margin-top: 30px;">
            This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        verification_url, verification_url, verification_url
    );

    let text_body = format!(
        "Welcome to Caution!\n\n\
         Thank you for registering. To complete your account setup, please verify your email address.\n\n\
         Click here to verify: {}\n\n\
         This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.\n\n\
         --\n\
         Caution Team",
        verification_url
    );

    let email = Message::builder()
        .from(
            format!("{} <{}>", state.from_name, state.from_email)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid from address: {}", e))?,
        )
        .to(req
            .email
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?)
        .subject("Verify Your Email - Caution")
        .header(ContentType::TEXT_HTML)
        .multipart(
            lettre::message::MultiPart::alternative()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build email: {}", e))?;

    let smtp_transport = state
        .smtp_transport
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SMTP transport not configured"))?;

    let result: SmtpResponse = smtp_transport
        .send(&email)
        .map_err(|e| anyhow::anyhow!("Failed to send email: {}", e))?;

    info!(
        "Email sent successfully to {}: {:?}",
        req.email,
        result.code()
    );

    Ok(Json(SendVerificationResponse {
        success: true,
        message: format!("Verification email sent to {}", req.email),
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    dotenvy::dotenv().ok();

    let test_mode = std::env::var("EMAIL_TEST_MODE")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    let from_email = std::env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@localhost".to_string());
    let from_name = std::env::var("FROM_NAME").unwrap_or_else(|_| "Caution".to_string());
    let base_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let smtp_transport = if test_mode {
        info!("EMAIL TEST MODE ENABLED - Emails will be logged instead of sent");
        None
    } else {
        let smtp_host = std::env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_port = std::env::var("SMTP_PORT")
            .expect("SMTP_PORT must be set")
            .parse::<u16>()
            .expect("SMTP_PORT must be a valid port number");
        let smtp_username = std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
        let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

        info!("Configuring SMTP transport: {}:{}", smtp_host, smtp_port);

        let creds = Credentials::new(smtp_username, smtp_password);
        let transport = SmtpTransport::relay(&smtp_host)?
            .port(smtp_port)
            .credentials(creds)
            .build();

        Some(Arc::new(transport))
    };

    let state = AppState {
        smtp_transport,
        from_email,
        from_name,
        base_url,
        test_mode,
    };

    info!("Email service configured successfully");

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/send-verification", post(send_verification_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082")
        .await?;

    info!("Email service listening on 0.0.0.0:8082");

    axum::serve(listener, app).await?;

    Ok(())
}

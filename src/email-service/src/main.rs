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
use std::sync::{Arc, Mutex};
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

#[derive(Debug, Clone, Serialize)]
struct SentEmail {
    to: String,
    template: String,
    subject: String,
    data: serde_json::Value,
    timestamp: String,
}

#[derive(Clone)]
struct AppState {
    smtp_transport: Option<Arc<SmtpTransport>>,
    from_email: String,
    from_name: String,
    base_url: String,
    test_mode: bool,
    /// In-memory store of sent emails (test mode only) for E2E verification
    sent_emails: Arc<Mutex<Vec<SentEmail>>>,
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

#[derive(Debug, Deserialize)]
struct SendEmailRequest {
    to: String,
    template: String,
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SendEmailResponse {
    success: bool,
    message: String,
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "email" }))
}

/// Query sent emails (test mode only). Supports optional ?template= and ?to= filters.
async fn get_sent_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if !state.test_mode {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "only available in test mode"}))).into_response();
    }

    let sent = state.sent_emails.lock().unwrap_or_else(|e| e.into_inner());
    let template_filter = params.get("template");
    let to_filter = params.get("to");

    let filtered: Vec<&SentEmail> = sent.iter()
        .filter(|e| template_filter.map_or(true, |t| &e.template == t))
        .filter(|e| to_filter.map_or(true, |t| &e.to == t))
        .collect();

    Json(serde_json::json!({
        "count": filtered.len(),
        "emails": filtered,
    })).into_response()
}

/// Clear sent emails store (test mode only).
async fn clear_sent_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !state.test_mode {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "only available in test mode"}))).into_response();
    }

    let mut sent = state.sent_emails.lock().unwrap_or_else(|e| e.into_inner());
    let count = sent.len();
    sent.clear();

    Json(serde_json::json!({
        "cleared": count,
    })).into_response()
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

        if let Ok(mut sent) = state.sent_emails.lock() {
            sent.push(SentEmail {
                to: req.email.clone(),
                template: "verification".to_string(),
                subject: "Verify Your Email - Caution".to_string(),
                data: serde_json::json!({
                    "user_id": req.user_id.to_string(),
                    "verification_url": verification_url,
                }),
                timestamp: format!("{:?}", std::time::SystemTime::now()),
            });
        }

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

// Generic email send handler with templates
async fn send_email_handler(
    State(state): State<AppState>,
    Json(req): Json<SendEmailRequest>,
) -> Result<Json<SendEmailResponse>, AppError> {
    info!("Sending {} email to: {}", req.template, req.to);

    let (subject, html_body, text_body) = match req.template.as_str() {
        "invoice" => generate_invoice_email(&req.data),
        "payment_confirmation" => generate_payment_confirmation_email(&req.data),
        "payment_failure" => generate_payment_failure_email(&req.data),
        "insufficient_balance" => generate_insufficient_balance_email(&req.data),
        "suspension_warning" => generate_suspension_warning_email(&req.data),
        "suspension_notice" => generate_suspension_notice_email(&req.data),
        _ => {
            return Ok(Json(SendEmailResponse {
                success: false,
                message: format!("Unknown template: {}", req.template),
            }));
        }
    };

    if state.test_mode {
        info!("");
        info!("========================================");
        info!("EMAIL TEST MODE - {}", req.template.to_uppercase());
        info!("========================================");
        info!("To: {}", req.to);
        info!("Subject: {}", subject);
        info!("Data: {}", serde_json::to_string_pretty(&req.data).unwrap_or_default());
        info!("========================================");
        info!("");

        if let Ok(mut sent) = state.sent_emails.lock() {
            sent.push(SentEmail {
                to: req.to.clone(),
                template: req.template.clone(),
                subject: subject.clone(),
                data: req.data.clone(),
                timestamp: format!("{:?}", std::time::SystemTime::now()),
            });
        }

        return Ok(Json(SendEmailResponse {
            success: true,
            message: format!("TEST MODE: {} email logged (not sent to {})", req.template, req.to),
        }));
    }

    let email = Message::builder()
        .from(
            format!("{} <{}>", state.from_name, state.from_email)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid from address: {}", e))?,
        )
        .to(req
            .to
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?)
        .subject(subject)
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
        req.to,
        result.code()
    );

    Ok(Json(SendEmailResponse {
        success: true,
        message: format!("{} email sent to {}", req.template, req.to),
    }))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}

fn generate_invoice_email(data: &serde_json::Value) -> (String, String, String) {
    let invoice_number_raw = data["invoice_number"].as_str().unwrap_or("N/A");
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");
    let date_raw = data["date"].as_str().unwrap_or("N/A");
    let pdf_url = data["pdf_url"].as_str();

    let invoice_number = html_escape(invoice_number_raw);
    let amount = html_escape(amount_raw);
    let date = html_escape(date_raw);

    let subject = format!("Invoice {} - Caution", invoice_number_raw);

    let pdf_link = pdf_url
        .map(|url| format!(r#"<p><a href="{}" style="color: #3498db;">Download Invoice PDF</a></p>"#, html_escape(url)))
        .unwrap_or_default();

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invoice</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #2c3e50; margin-top: 0;">Invoice {}</h1>

        <p>Your invoice is ready.</p>

        <div style="background-color: white; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="color: #7f8c8d;">Invoice Number:</td>
                    <td style="text-align: right; font-weight: bold;">{}</td>
                </tr>
                <tr>
                    <td style="color: #7f8c8d;">Date:</td>
                    <td style="text-align: right;">{}</td>
                </tr>
                <tr>
                    <td style="color: #7f8c8d; padding-top: 10px; border-top: 1px solid #eee;">Amount Due:</td>
                    <td style="text-align: right; font-weight: bold; font-size: 1.2em; padding-top: 10px; border-top: 1px solid #eee;">{}</td>
                </tr>
            </table>
        </div>

        {}

        <p style="color: #7f8c8d; font-size: 14px;">
            If you have any questions about this invoice, please contact support.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        invoice_number, invoice_number, date, amount, pdf_link
    );

    let text_body = format!(
        "Invoice {}\n\n\
         Your invoice is ready.\n\n\
         Invoice Number: {}\n\
         Date: {}\n\
         Amount Due: {}\n\n\
         If you have any questions, please contact support.\n\n\
         --\n\
         Caution Team",
        invoice_number_raw, invoice_number_raw, date_raw, amount_raw
    );

    (subject, html_body, text_body)
}

fn generate_payment_confirmation_email(data: &serde_json::Value) -> (String, String, String) {
    let invoice_number_raw = data["invoice_number"].as_str().unwrap_or("N/A");
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");

    let invoice_number = html_escape(invoice_number_raw);
    let amount = html_escape(amount_raw);

    let subject = format!("Payment Received - Invoice {}", invoice_number_raw);

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Payment Confirmation</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #27ae60; margin-top: 0;">Payment Received</h1>

        <p>Thank you! We've received your payment.</p>

        <div style="background-color: white; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="color: #7f8c8d;">Invoice Number:</td>
                    <td style="text-align: right; font-weight: bold;">{}</td>
                </tr>
                <tr>
                    <td style="color: #7f8c8d;">Amount Paid:</td>
                    <td style="text-align: right; font-weight: bold; color: #27ae60;">{}</td>
                </tr>
            </table>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            Your account is in good standing. Thank you for using Caution!
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        invoice_number, amount
    );

    let text_body = format!(
        "Payment Received\n\n\
         Thank you! We've received your payment.\n\n\
         Invoice Number: {}\n\
         Amount Paid: {}\n\n\
         Your account is in good standing. Thank you for using Caution!\n\n\
         --\n\
         Caution Team",
        invoice_number_raw, amount_raw
    );

    (subject, html_body, text_body)
}

fn generate_payment_failure_email(data: &serde_json::Value) -> (String, String, String) {
    let invoice_number_raw = data["invoice_number"].as_str().unwrap_or("N/A");
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");

    let invoice_number = html_escape(invoice_number_raw);
    let amount = html_escape(amount_raw);

    let subject = format!("Payment Failed - Invoice {}", invoice_number_raw);

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Payment Failed</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #e74c3c; margin-top: 0;">Payment Failed</h1>

        <p>We were unable to process your payment.</p>

        <div style="background-color: white; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="color: #7f8c8d;">Invoice Number:</td>
                    <td style="text-align: right; font-weight: bold;">{}</td>
                </tr>
                <tr>
                    <td style="color: #7f8c8d;">Amount Due:</td>
                    <td style="text-align: right; font-weight: bold; color: #e74c3c;">{}</td>
                </tr>
            </table>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <a href="https://caution.co/billing"
               style="background-color: #3498db; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Update Payment Method
            </a>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            Please update your payment method to avoid service interruption.
            If you believe this is an error, please contact support.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        invoice_number, amount
    );

    let text_body = format!(
        "Payment Failed\n\n\
         We were unable to process your payment.\n\n\
         Invoice Number: {}\n\
         Amount Due: {}\n\n\
         Please update your payment method at https://caution.co/billing to avoid service interruption.\n\n\
         If you believe this is an error, please contact support.\n\n\
         --\n\
         Caution Team",
        invoice_number_raw, amount_raw
    );

    (subject, html_body, text_body)
}

fn generate_insufficient_balance_email(data: &serde_json::Value) -> (String, String, String) {
    let invoice_number_raw = data["invoice_number"].as_str().unwrap_or("N/A");
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");
    let topup_url_raw = data["topup_url"].as_str().unwrap_or("https://caution.co/billing/topup");

    let invoice_number = html_escape(invoice_number_raw);
    let amount = html_escape(amount_raw);
    let topup_url = html_escape(topup_url_raw);

    let subject = format!("Action Required: Insufficient Balance - Invoice {}", invoice_number_raw);

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Insufficient Balance</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #f39c12; margin-top: 0;">Insufficient Balance</h1>

        <p>Your account balance is insufficient to cover your latest invoice.</p>

        <div style="background-color: white; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="color: #7f8c8d;">Invoice Number:</td>
                    <td style="text-align: right; font-weight: bold;">{}</td>
                </tr>
                <tr>
                    <td style="color: #7f8c8d;">Amount Due:</td>
                    <td style="text-align: right; font-weight: bold;">{}</td>
                </tr>
            </table>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #27ae60; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Add Funds to Your Account
            </a>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            Please add funds to your account to continue using Caution services.
            Your services may be suspended if the balance is not replenished.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        invoice_number, amount, topup_url
    );

    let text_body = format!(
        "Insufficient Balance\n\n\
         Your account balance is insufficient to cover your latest invoice.\n\n\
         Invoice Number: {}\n\
         Amount Due: {}\n\n\
         Please add funds at {} to continue using Caution services.\n\n\
         Your services may be suspended if the balance is not replenished.\n\n\
         --\n\
         Caution Team",
        invoice_number_raw, amount_raw, topup_url_raw
    );

    (subject, html_body, text_body)
}

fn generate_suspension_warning_email(data: &serde_json::Value) -> (String, String, String) {
    let days_remaining = data["days_remaining"].as_i64().unwrap_or(4);
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");
    let amount = html_escape(amount_raw);

    let subject = "Action Required: Your services will be suspended".to_string();

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Suspension Warning</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #e67e22; margin-top: 0;">Your Services Will Be Suspended</h1>

        <p>We've been unable to collect payment of <strong>{}</strong> for your account.</p>

        <p style="color: #e74c3c; font-weight: bold;">
            Your running deployments will be suspended in {} days if payment is not received.
        </p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="https://caution.dev/settings/billing"
               style="background-color: #e74c3c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Update Payment Method
            </a>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            Suspended instances are stopped but not destroyed. Once payment is received,
            your services will be automatically restored.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        amount, days_remaining
    );

    let text_body = format!(
        "Your Services Will Be Suspended\n\n\
         We've been unable to collect payment of {} for your account.\n\n\
         Your running deployments will be suspended in {} days if payment is not received.\n\n\
         Update your payment method at https://caution.dev/settings/billing\n\n\
         Suspended instances are stopped but not destroyed. Once payment is received, \
         your services will be automatically restored.\n\n\
         --\n\
         Caution Team",
        amount_raw, days_remaining
    );

    (subject, html_body, text_body)
}

fn generate_suspension_notice_email(data: &serde_json::Value) -> (String, String, String) {
    let amount_raw = data["amount"].as_str().unwrap_or("$0.00");
    let amount = html_escape(amount_raw);
    let app_count = data["app_count"].as_i64().unwrap_or(0);

    let subject = "Your services have been suspended".to_string();

    let html_body = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Services Suspended</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
        <h1 style="color: #e74c3c; margin-top: 0;">Your Services Have Been Suspended</h1>

        <p>Due to non-payment of <strong>{}</strong>, we have stopped <strong>{}</strong> running deployment(s).</p>

        <p>Your data has <strong>not</strong> been deleted. Once payment is received, your services will be automatically restored.</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="https://caution.dev/settings/billing"
               style="background-color: #27ae60; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Resolve Payment &amp; Restore Services
            </a>
        </div>

        <p style="color: #7f8c8d; font-size: 14px;">
            If you no longer need these services, you can destroy them in your dashboard
            to stop further charges.
        </p>
    </div>

    <p style="color: #95a5a6; font-size: 12px; text-align: center; margin-top: 20px;">
        &copy; 2025 Caution. All rights reserved.
    </p>
</body>
</html>
        "#,
        amount, app_count
    );

    let text_body = format!(
        "Your Services Have Been Suspended\n\n\
         Due to non-payment of {}, we have stopped {} running deployment(s).\n\n\
         Your data has NOT been deleted. Once payment is received, your services \
         will be automatically restored.\n\n\
         Resolve payment at https://caution.dev/settings/billing\n\n\
         --\n\
         Caution Team",
        amount_raw, app_count
    );

    (subject, html_body, text_body)
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
        let transport = if smtp_port == 465 {
            SmtpTransport::relay(&smtp_host)?
                .port(smtp_port)
                .credentials(creds)
                .build()
        } else {
            SmtpTransport::starttls_relay(&smtp_host)?
                .port(smtp_port)
                .credentials(creds)
                .build()
        };

        Some(Arc::new(transport))
    };

    let state = AppState {
        smtp_transport,
        from_email,
        from_name,
        base_url,
        test_mode,
        sent_emails: Arc::new(Mutex::new(Vec::new())),
    };

    info!("Email service configured successfully");

    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/send-verification", post(send_verification_handler))
        .route("/send", post(send_email_handler));

    if test_mode {
        app = app
            .route("/sent", get(get_sent_handler).delete(clear_sent_handler));
        info!("Test mode: GET /sent and DELETE /sent endpoints enabled");
    }

    let app = app
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_addr = std::env::var("EMAIL_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8082".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await?;

    info!("Email service listening on {}", bind_addr);

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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- suspension_warning template ----

    #[test]
    fn test_suspension_warning_email_content() {
        let data = serde_json::json!({
            "days_remaining": 4,
            "amount": "$25.00",
        });
        let (subject, html, text) = generate_suspension_warning_email(&data);

        assert_eq!(subject, "Action Required: Your services will be suspended");
        assert!(html.contains("$25.00"));
        assert!(html.contains("4 days"));
        assert!(html.contains("https://caution.dev/settings/billing"));
        assert!(text.contains("$25.00"));
        assert!(text.contains("4 days"));
        assert!(text.contains("https://caution.dev/settings/billing"));
    }

    #[test]
    fn test_suspension_warning_email_defaults() {
        let data = serde_json::json!({});
        let (subject, html, text) = generate_suspension_warning_email(&data);

        assert_eq!(subject, "Action Required: Your services will be suspended");
        // defaults: amount = "$0.00", days_remaining = 4
        assert!(html.contains("$0.00"));
        assert!(html.contains("4 days"));
        assert!(text.contains("$0.00"));
        assert!(text.contains("4 days"));
    }

    #[test]
    fn test_suspension_warning_email_custom_days() {
        let data = serde_json::json!({
            "days_remaining": 1,
            "amount": "$5.00",
        });
        let (_, html, text) = generate_suspension_warning_email(&data);

        assert!(html.contains("1 days"));
        assert!(text.contains("1 days"));
    }

    // ---- suspension_notice template ----

    #[test]
    fn test_suspension_notice_email_content() {
        let data = serde_json::json!({
            "amount": "$42.50",
            "app_count": 3,
        });
        let (subject, html, text) = generate_suspension_notice_email(&data);

        assert_eq!(subject, "Your services have been suspended");
        assert!(html.contains("$42.50"));
        assert!(html.contains("<strong>3</strong> running deployment(s)"));
        assert!(html.contains("has <strong>not</strong> been deleted"));
        assert!(html.contains("https://caution.dev/settings/billing"));
        assert!(text.contains("$42.50"));
        assert!(text.contains("3 running deployment(s)"));
        assert!(text.contains("has NOT been deleted"));
    }

    #[test]
    fn test_suspension_notice_email_defaults() {
        let data = serde_json::json!({});
        let (subject, html, text) = generate_suspension_notice_email(&data);

        assert_eq!(subject, "Your services have been suspended");
        // defaults: amount = "$0.00", app_count = 0
        assert!(html.contains("$0.00"));
        assert!(html.contains("<strong>0</strong> running deployment(s)"));
        assert!(text.contains("$0.00"));
        assert!(text.contains("0 running deployment(s)"));
    }

    #[test]
    fn test_suspension_notice_email_single_app() {
        let data = serde_json::json!({
            "amount": "$10.00",
            "app_count": 1,
        });
        let (_, html, text) = generate_suspension_notice_email(&data);
        assert!(html.contains("<strong>1</strong> running deployment(s)"));
        assert!(text.contains("1 running deployment(s)"));
    }

    // ---- template dispatch ----

    #[test]
    fn test_all_templates_dispatched() {
        // Verify the template names match what the dunning loop sends
        let templates = vec![
            "invoice",
            "payment_confirmation",
            "payment_failure",
            "insufficient_balance",
            "suspension_warning",
            "suspension_notice",
        ];

        for template in templates {
            let data = serde_json::json!({
                "invoice_number": "INV-001",
                "amount": "$10.00",
                "date": "2025-01-01",
                "days_remaining": 4,
                "app_count": 1,
            });

            let result = match template {
                "invoice" => generate_invoice_email(&data),
                "payment_confirmation" => generate_payment_confirmation_email(&data),
                "payment_failure" => generate_payment_failure_email(&data),
                "insufficient_balance" => generate_insufficient_balance_email(&data),
                "suspension_warning" => generate_suspension_warning_email(&data),
                "suspension_notice" => generate_suspension_notice_email(&data),
                _ => panic!("Unknown template: {}", template),
            };

            let (subject, html, text) = result;
            assert!(!subject.is_empty(), "Subject empty for template: {}", template);
            assert!(!html.is_empty(), "HTML empty for template: {}", template);
            assert!(!text.is_empty(), "Text empty for template: {}", template);
            assert!(html.contains("</html>"), "HTML not well-formed for template: {}", template);
            assert!(text.contains("Caution"), "Text missing branding for template: {}", template);
        }
    }

    // ---- existing templates still work ----

    #[test]
    fn test_payment_failure_email_has_update_link() {
        let data = serde_json::json!({
            "invoice_number": "INV-123",
            "amount": "$15.00",
        });
        let (subject, html, text) = generate_payment_failure_email(&data);

        assert!(subject.contains("Payment Failed"));
        assert!(html.contains("Update Payment Method"));
        assert!(text.contains("update your payment method"));
    }
}

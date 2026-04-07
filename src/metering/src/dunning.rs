// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use std::sync::Arc;

use crate::AppState;

/// Runs every hour. Detects delinquent orgs, sends escalating emails, and
/// suspends resources after 7 days of non-payment.
pub async fn run_dunning_loop(state: Arc<AppState>) {
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
        JOIN wallet_balance wb ON wb.organization_id = o.id
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
            SELECT 1 FROM wallet_balance wb
            WHERE wb.organization_id = $1 AND wb.balance_cents >= 0
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
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
pub(crate) async fn send_dunning_email(state: &AppState, org_id: uuid::Uuid, template: &str, data: serde_json::Value) {
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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

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

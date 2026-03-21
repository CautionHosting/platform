// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use sqlx::Row;

use crate::AppState;
use crate::dunning::send_dunning_email;
use crate::paddle;

/// After deducting credits, check if the user's balance requires action.
pub(crate) async fn check_balance_thresholds(state: &AppState, user_id: uuid::Uuid) -> Result<()> {
    let balance_cents: i64 = sqlx::query_scalar(
        "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or(0);

    // Read billing config for auto-topup settings
    let config = sqlx::query(
        r#"SELECT auto_topup_enabled, auto_topup_amount_dollars,
                  low_balance_warned_at, last_auto_topup_at, paddle_customer_id
           FROM billing_config WHERE user_id = $1"#
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let auto_topup_enabled = config.as_ref()
        .and_then(|r| r.get::<Option<bool>, _>("auto_topup_enabled"))
        .unwrap_or(false);
    let auto_topup_dollars: i32 = config.as_ref()
        .and_then(|r| r.get::<Option<i32>, _>("auto_topup_amount_dollars"))
        .unwrap_or(0);
    let low_balance_warned_at: Option<chrono::DateTime<chrono::Utc>> = config.as_ref()
        .and_then(|r| r.get("low_balance_warned_at"));
    let last_auto_topup_at: Option<chrono::DateTime<chrono::Utc>> = config.as_ref()
        .and_then(|r| r.get("last_auto_topup_at"));
    let paddle_customer_id: Option<String> = config.as_ref()
        .and_then(|r| r.get("paddle_customer_id"));

    // Look up user's org
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(org_id) = org_id else {
        return Ok(());
    };

    let now = chrono::Utc::now();

    // Priority 1: Balance <= 0 → suspend fully-managed resources + trigger auto-topup if enabled
    if balance_cents <= 0 {
        let already_suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT credit_suspended_at FROM organizations WHERE id = $1"
        )
        .bind(org_id)
        .fetch_optional(&state.pool)
        .await?
        .flatten();

        if already_suspended.is_none() {
            tracing::warn!("User {} balance {} <= 0, suspending fully-managed resources", user_id, balance_cents);
            suspend_fully_managed_org(state, org_id).await;
        }

        // If auto-topup is enabled, trigger it so the user can auto-recover after suspension
        if auto_topup_enabled && auto_topup_dollars > 0 {
            let target_cents = (auto_topup_dollars as i64) * 100;
            let cooldown_ok = last_auto_topup_at
                .map(|t| (now - t).num_seconds() > 300)
                .unwrap_or(true);
            if cooldown_ok {
                if let Some(customer_id) = paddle_customer_id.as_ref() {
                    tracing::info!("Triggering auto-topup for suspended user {} to enable recovery", user_id);
                    trigger_auto_topup(state, user_id, balance_cents, target_cents, customer_id).await;
                }
            }
        }

        return Ok(());
    }

    // Priority 2: Auto top-up enabled and balance < 5% of target (pre-emptive top-up)
    if auto_topup_enabled && auto_topup_dollars > 0 {
        let target_cents = (auto_topup_dollars as i64) * 100;
        let threshold = target_cents / 20; // 5%
        if balance_cents < threshold {
            let cooldown_ok = last_auto_topup_at
                .map(|t| (now - t).num_seconds() > 300)
                .unwrap_or(true);
            if cooldown_ok {
                if let Some(customer_id) = paddle_customer_id.as_ref() {
                    trigger_auto_topup(state, user_id, balance_cents, target_cents, customer_id).await;
                }
            }
        }
        return Ok(());
    }

    // Priority 3: No auto top-up, balance < $5 (500 cents) → warn
    if balance_cents < 500 {
        let cooldown_ok = low_balance_warned_at
            .map(|t| (now - t).num_seconds() > 86400) // >24h
            .unwrap_or(true);
        if cooldown_ok {
            tracing::info!("Low balance warning for user {} ({}c)", user_id, balance_cents);

            if let Err(e) = sqlx::query(
                "UPDATE billing_config SET low_balance_warned_at = NOW() WHERE user_id = $1"
            )
            .bind(user_id)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to update low_balance_warned_at for user {}: {}", user_id, e);
            }

            send_dunning_email(state, org_id, "insufficient_balance", serde_json::json!({
                "balance": format!("${:.2}", balance_cents as f64 / 100.0),
                "amount": format!("${:.2}", balance_cents as f64 / 100.0),
                "add_credits_url": "https://caution.dev/settings/billing",
            })).await;
        }
    }

    Ok(())
}

/// Suspend only fully-managed resources for an org (not managed on-prem).
pub(crate) async fn suspend_fully_managed_org(state: &AppState, org_id: uuid::Uuid) {
    // Set credit_suspended_at
    if let Err(e) = sqlx::query(
        "UPDATE organizations SET credit_suspended_at = NOW() WHERE id = $1 AND credit_suspended_at IS NULL"
    )
    .bind(org_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to set credit_suspended_at for org {}: {}", org_id, e);
    }

    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());
    let Some(ref internal_secret) = state.internal_service_secret else {
        tracing::error!("INTERNAL_SERVICE_SECRET not configured — cannot call API to suspend managed resources for org {}", org_id);
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
        tracing::error!("No members found for org {}, cannot suspend", org_id);
        return;
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/internal/org/{}/suspend-managed", api_url, org_id))
        .header("x-internal-service-secret", internal_secret.as_str())
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Suspended fully-managed resources for org {}", org_id);

            send_dunning_email(state, org_id, "suspension_notice", serde_json::json!({
                "reason": "credit_exhaustion",
                "add_credits_url": "https://caution.dev/settings/billing",
            })).await;
        }
        Ok(r) => {
            tracing::error!("API returned {} when suspending managed resources for org {}", r.status(), org_id);
        }
        Err(e) => {
            tracing::error!("Failed to call API to suspend managed resources for org {}: {}", org_id, e);
        }
    }
}

/// Trigger auto top-up by creating a Paddle transaction for `target - current_balance`.
pub(crate) async fn trigger_auto_topup(
    state: &AppState,
    user_id: uuid::Uuid,
    current_balance: i64,
    target_cents: i64,
    paddle_customer_id: &str,
) {
    let topup_cents = target_cents - current_balance;
    if topup_cents <= 0 {
        return;
    }

    tracing::info!(
        "Auto top-up: user={}, current={}c, target={}c, charging={}c",
        user_id, current_balance, target_cents, topup_cents
    );

    // Optimistic: set last_auto_topup_at to prevent rapid-fire
    if let Err(e) = sqlx::query(
        "UPDATE billing_config SET last_auto_topup_at = NOW() WHERE user_id = $1"
    )
    .bind(user_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to set last_auto_topup_at for user {}: {}", user_id, e);
    }

    let topup_dollars = topup_cents as f64 / 100.0;
    let line_items = vec![paddle::LineItem {
        description: format!("Auto top-up: ${:.2}", topup_dollars),
        quantity: 1,
        unit_price_amount: format!("{}", topup_cents),
        unit_price_currency: "USD".to_string(),
    }];

    // Retry up to 3 times with exponential backoff
    let mut last_err = None;
    for attempt in 0..3 {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(1 << attempt); // 2s, 4s
            tracing::info!("Auto top-up retry {} for user {} in {:?}", attempt + 1, user_id, delay);
            tokio::time::sleep(delay).await;
        }

        match state.paddle.create_transaction(paddle_customer_id, line_items.clone()).await {
            Ok(txn) => {
                tracing::info!(
                    "Created Paddle auto-topup transaction {} for user {} (${:.2})",
                    txn.id, user_id, topup_dollars
                );
                // Credits will be deposited when transaction.completed webhook fires
                return;
            }
            Err(e) => {
                tracing::warn!("Auto top-up attempt {} failed for user {}: {}", attempt + 1, user_id, e);
                last_err = Some(e);
            }
        }
    }

    // All retries exhausted — clear last_auto_topup_at so the next collection cycle can retry
    tracing::error!("Auto top-up failed after 3 attempts for user {}: {}", user_id, last_err.unwrap());
    if let Err(e) = sqlx::query(
        "UPDATE billing_config SET last_auto_topup_at = NULL WHERE user_id = $1"
    )
    .bind(user_id)
    .execute(&state.pool)
    .await {
        tracing::error!("Failed to clear last_auto_topup_at for user {}: {}", user_id, e);
    }

    // Send payment failure email
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    if let Some(org_id) = org_id {
        send_dunning_email(state, org_id, "payment_failure", serde_json::json!({
            "reason": "auto_topup_failed",
            "update_payment_url": "https://caution.dev/settings/billing",
        })).await;
    }
}

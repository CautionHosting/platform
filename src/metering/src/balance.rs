// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use sqlx::Row;

use crate::credits::get_ledger_balance_cents;
use crate::dunning::send_dunning_email;
use crate::AppState;

const LOW_BALANCE_WARNING_CENTS: i64 = 2_500;

/// After deducting credits, check if the org's balance requires action.
pub(crate) async fn check_balance_thresholds(state: &AppState, org_id: uuid::Uuid) -> Result<()> {
    let balance_cents = get_ledger_balance_cents(&state.pool, org_id).await?;

    // Read billing config for warning cooldown state.
    let config = sqlx::query(
        r#"SELECT low_balance_warned_at
           FROM billing_config WHERE organization_id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?;
    let low_balance_warned_at: Option<chrono::DateTime<chrono::Utc>> =
        config.as_ref().and_then(|r| r.get("low_balance_warned_at"));

    let now = chrono::Utc::now();

    // Priority 1: Balance <= 0 → suspend fully-managed resources.
    if balance_cents <= 0 {
        let already_suspended: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                .bind(org_id)
                .fetch_optional(&state.pool)
                .await?
                .flatten();

        if already_suspended.is_none() {
            tracing::warn!(
                "Org {} balance {} <= 0, suspending fully-managed resources",
                org_id,
                balance_cents
            );
            suspend_fully_managed_org(state, org_id).await;
        }

        return Ok(());
    }

    // Priority 2: Balance below deploy minimum → warn
    if balance_cents < LOW_BALANCE_WARNING_CENTS {
        let cooldown_ok = low_balance_warned_at
            .map(|t| (now - t).num_seconds() > 86400) // >24h
            .unwrap_or(true);
        if cooldown_ok {
            tracing::info!(
                "Low balance warning for org {} ({}c)",
                org_id,
                balance_cents
            );

            if let Err(e) = sqlx::query(
                "UPDATE billing_config SET low_balance_warned_at = NOW() WHERE organization_id = $1"
            )
            .bind(org_id)
            .execute(&state.pool)
            .await {
                tracing::error!("Failed to update low_balance_warned_at for org {}: {}", org_id, e);
            }

            send_dunning_email(
                state,
                org_id,
                "insufficient_balance",
                serde_json::json!({
                    "balance": format!("${:.2}", balance_cents as f64 / 100.0),
                    "amount": format!("${:.2}", balance_cents as f64 / 100.0),
                    "add_credits_url": crate::BILLING_URL,
                }),
            )
            .await;
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

    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
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
        .post(format!(
            "{}/internal/org/{}/suspend-managed",
            api_url, org_id
        ))
        .header(
            "x-internal-service-secret",
            state.internal_service_secret.as_str(),
        )
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("Suspended fully-managed resources for org {}", org_id);

            send_dunning_email(
                state,
                org_id,
                "suspension_notice",
                serde_json::json!({
                    "reason": "credit_exhaustion",
                    "add_credits_url": crate::BILLING_URL,
                }),
            )
            .await;
        }
        Ok(r) => {
            tracing::error!(
                "API returned {} when suspending managed resources for org {}",
                r.status(),
                org_id
            );
        }
        Err(e) => {
            tracing::error!(
                "Failed to call API to suspend managed resources for org {}: {}",
                org_id,
                e
            );
        }
    }
}

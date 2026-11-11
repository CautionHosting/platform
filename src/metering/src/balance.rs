// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::Row;

use crate::credits::get_ledger_balance_cents;
use crate::handlers::send_dunning_email;
use crate::AppState;

const LOW_BALANCE_WARNING_CENTS: i64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CheckBalanceThresholdsErrorKind {
    GetBalance,
    ReadBillingConfig,
    ReadSuspendedAt,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("could not check balance thresholds ({kind:?}) [{location}]")]
pub(crate) struct CheckBalanceThresholdsError {
    kind: CheckBalanceThresholdsErrorKind,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

/// After deducting credits, check if the org's balance requires action.
#[tracing::instrument(skip_all, fields(org_id = %org_id))]
pub(crate) async fn check_balance_thresholds(
    state: &AppState,
    org_id: uuid::Uuid,
) -> Result<(), CheckBalanceThresholdsError> {
    use CheckBalanceThresholdsErrorCtx as Ctx;

    let balance_cents = get_ledger_balance_cents(&state.pool, org_id)
        .await
        .with_context(Ctx::new(CheckBalanceThresholdsErrorKind::GetBalance))?;

    // Read billing config for warning cooldown state.
    let config = sqlx::query(
        r#"SELECT low_balance_warned_at
           FROM billing_config WHERE organization_id = $1"#,
    )
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .with_context(Ctx::new(CheckBalanceThresholdsErrorKind::ReadBillingConfig))?;
    let low_balance_warned_at: Option<chrono::DateTime<chrono::Utc>> =
        config.as_ref().and_then(|r| r.get("low_balance_warned_at"));

    let now = chrono::Utc::now();

    // Priority 1: Balance <= 0 → suspend fully-managed resources.
    if balance_cents <= 0 {
        let already_suspended: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                .bind(org_id)
                .fetch_optional(&state.pool)
                .await
                .with_context(Ctx::new(CheckBalanceThresholdsErrorKind::ReadSuspendedAt))?
                .flatten();

        // credit_suspended_at is only set once the API confirms every
        // resource stopped, so an unset flag here means "not stopped yet":
        // retry on every cycle until the suspension succeeds.
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
///
/// Failures are logged, not propagated: the org is left unflagged so the next
/// balance check retries the suspension.
#[tracing::instrument(skip_all, fields(org_id = %org_id))]
pub(crate) async fn suspend_fully_managed_org(state: &AppState, org_id: uuid::Uuid) {
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8080".to_string());

    match request_managed_suspension(
        &state.pool,
        &api_url,
        &state.internal_service_secret,
        org_id,
    )
    .await
    {
        Ok(true) => {
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
        // Already marked by an earlier cycle: the notice was sent then.
        Ok(false) => {}
        Err(e) => {
            tracing::error!(
                "Failed to suspend managed resources for org {}, will retry next cycle: {}",
                org_id,
                e
            );
        }
    }
}

/// Which step of [`request_managed_suspension`] failed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RequestManagedSuspensionErrorKind {
    /// The query for an org member to authenticate as failed.
    ReadMember,
    /// The org has no members, so the API call cannot be authenticated.
    NoMembers,
    /// The request to the API failed or timed out.
    Send,
    /// The API answered with a failure status. A partial stop reports 502.
    Status { code: u16 },
    /// The resources stopped but the suspension flag could not be written.
    MarkSuspended,
}

/// A failed credit suspension. The org is left unflagged so the next balance
/// check retries.
#[derive(Debug, thiserror::Error, CtxError)]
#[error("could not suspend managed resources for org {org_id} ({kind:?}) [{location}]")]
pub(crate) struct RequestManagedSuspensionError {
    kind: RequestManagedSuspensionErrorKind,
    org_id: uuid::Uuid,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

/// Ask the API to stop an org's fully-managed resources, then mark the org
/// credit-suspended.
///
/// The flag is written only after the API reports that every resource
/// stopped. Marking first would let a failed or partial stop leave resources
/// running (and billing) while every later balance check skipped the org as
/// already suspended.
///
/// Returns `true` when this call set the flag, and `false` when the org was
/// already marked (so the suspension notice is sent only once).
///
/// # Errors
///
/// Returns [`RequestManagedSuspensionError`] when no org member can be found,
/// the API is unreachable, the API reports any resource that failed to stop,
/// or the flag cannot be written. The flag is never set in these cases.
pub(crate) async fn request_managed_suspension(
    pool: &sqlx::PgPool,
    api_url: &str,
    internal_service_secret: &str,
    org_id: uuid::Uuid,
) -> Result<bool, RequestManagedSuspensionError> {
    use RequestManagedSuspensionErrorCtx as Ctx;
    use RequestManagedSuspensionErrorKind as Kind;

    let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM organization_members WHERE organization_id = $1 LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::new(Kind::ReadMember, org_id))?;

    let Some(user_id) = user_id else {
        return Err(RequestManagedSuspensionError {
            kind: Kind::NoMembers,
            org_id,
            location: std::panic::Location::caller(),
            source: None,
        });
    };

    // Stopping instances is sequential on the API side; allow for orgs with
    // many resources. A timeout is safe: the next cycle retries.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp = client
        .post(format!("{}/internal/org/{}/suspend-managed", api_url, org_id))
        .header("x-internal-service-secret", internal_service_secret)
        .header("x-authenticated-user-id", user_id.to_string())
        .send()
        .await
        .with_context(Ctx::new(Kind::Send, org_id))?;

    // The response body is not read: the API logs per-resource failures
    // itself, and an unbounded body has no place in this service's logs.
    let status = resp.status();
    if !status.is_success() {
        return Err(RequestManagedSuspensionError {
            kind: Kind::Status {
                code: status.as_u16(),
            },
            org_id,
            location: std::panic::Location::caller(),
            source: None,
        });
    }

    let marked = sqlx::query(
        "UPDATE organizations SET credit_suspended_at = NOW() WHERE id = $1 AND credit_suspended_at IS NULL",
    )
    .bind(org_id)
    .execute(pool)
    .await
    .with_context(Ctx::new(Kind::MarkSuspended, org_id))?;

    Ok(marked.rows_affected() == 1)
}

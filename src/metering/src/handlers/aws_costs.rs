// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use std::sync::Arc;

use crate::cost_explorer;
use crate::AppState;

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SyncAwsCostsError {
    #[error("could not sync AWS costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SyncAwsCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "sync AWS costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAwsOrgCostsError {
    #[error("could not get AWS org costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetAwsOrgCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get AWS org costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAllAwsCostsError {
    #[error("could not get all AWS costs [{location}]")]
    Aws {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetAllAwsCostsError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get all AWS costs error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct SyncAwsCostsRequest {
    /// Start date in YYYY-MM-DD format (defaults to first of current month)
    start_date: Option<String>,
    /// End date in YYYY-MM-DD format (defaults to today)
    end_date: Option<String>,
}

/// Sync costs from AWS Cost Explorer for all orgs and record as usage
#[tracing::instrument(skip_all, err)]
pub(crate) async fn sync_aws_costs(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SyncAwsCostsRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), SyncAwsCostsError> {
    use SyncAwsCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = req.start_date.unwrap_or(default_start);
    let end_date = req.end_date.unwrap_or(default_end);

    tracing::info!("Syncing AWS costs from {} to {}", start_date, end_date);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    let mut synced_count = 0;
    let mut total_cost = 0.0;

    for (org_id, cost_data) in &org_costs {
        let parsed_org_id: uuid::Uuid = match org_id.parse() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!("Skipping non-UUID org_id: {}", org_id);
                continue;
            }
        };

        let now = time::OffsetDateTime::now_utc();
        let result = sqlx::query(
            r#"
            INSERT INTO usage_ledger (
                organization_id, application_id, resource_id, provider, resource_type,
                quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
            )
            VALUES ($1, NULL, $2, 'aws', 'aws_cost_explorer', $3, 'usd', 1, 0, $4, $5)
            "#,
        )
        .bind(parsed_org_id)
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
            }
            Err(e) => {
                tracing::error!("Failed to record costs for org {}: {}", org_id, e);
            }
        }
    }

    Ok((
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
    ))
}

#[derive(serde::Deserialize)]
pub(crate) struct GetAwsCostsQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

/// Get AWS costs for a specific org
#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub(crate) async fn get_aws_org_costs(
    axum::extract::Path(org_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetAwsOrgCostsError> {
    use GetAwsOrgCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let cost_data = ce_client
        .get_org_costs(&org_id, &start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    Ok((StatusCode::OK, Json(serde_json::json!(cost_data))))
}

/// Get AWS costs for all orgs (summary)
#[tracing::instrument(skip_all, err)]
pub(crate) async fn get_all_aws_costs(
    axum::extract::Query(query): axum::extract::Query<GetAwsCostsQuery>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetAllAwsCostsError> {
    use GetAllAwsCostsErrorCtx as Ctx;

    let (default_start, default_end) = cost_explorer::current_billing_period();
    let start_date = query.start_date.unwrap_or(default_start);
    let end_date = query.end_date.unwrap_or(default_end);

    let ce_client = cost_explorer::CostExplorerClient::new()
        .await
        .with_context(Ctx::aws())?;

    let org_costs = ce_client
        .get_all_org_costs(&start_date, &end_date)
        .await
        .with_context(Ctx::aws())?;

    let total: f64 = org_costs.values().map(|c| c.total_cost).sum();

    Ok((
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
    ))
}

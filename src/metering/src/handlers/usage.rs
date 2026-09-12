// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::Row;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetUserUsageError {
    #[error("could not get user usage [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetUserUsageError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "get user usage error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %user_id))]
pub(crate) async fn get_user_usage(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), GetUserUsageError> {
    use GetUserUsageErrorCtx as Ctx;

    let rows = sqlx::query(
        r#"
        SELECT
            provider,
            resource_type,
            quantity::float8           AS quantity,
            base_unit_cost_usd::float8 AS base_unit_cost_usd,
            margin_percent::float8     AS margin_percent
        FROM usage_ledger
        WHERE user_id = $1
        AND recorded_at >= NOW() - INTERVAL '30 days'
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .with_context(Ctx::database())?;

    let mut usage_map = std::collections::BTreeMap::<(String, String), (f64, f64)>::new();

    for row in &rows {
        let provider = row.get::<String, _>("provider");
        let resource_type = row.get::<String, _>("resource_type");
        let quantity = row.get::<f64, _>("quantity");
        let base_unit_cost_usd = row.get::<f64, _>("base_unit_cost_usd");
        let margin_percent = row.get::<f64, _>("margin_percent");
        let total_cost = crate::calculator::PricingBreakdown {
            base_unit_cost_usd,
            margin_percent,
        }
        .total_cost_usd(quantity);

        let entry = usage_map
            .entry((provider, resource_type))
            .or_insert((0.0, 0.0));
        entry.0 += quantity;
        entry.1 += total_cost;
    }

    let usage: Vec<serde_json::Value> = usage_map
        .into_iter()
        .map(|((provider, resource_type), (total_quantity, total_cost))| {
            serde_json::json!({
                "provider": provider,
                "resource_type": resource_type,
                "total_quantity": total_quantity,
                "total_cost": total_cost,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(serde_json::json!({"usage": usage}))))
}

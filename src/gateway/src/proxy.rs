// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use reqwest::Client;

use crate::types::AppState;

pub async fn proxy_handler(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, Response> {
    let client = Client::new();

    let path = req.uri().path();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    let target_url = format!("{}{}{}", state.api_service_url, path, query);
    
    tracing::debug!("Proxying request to: {}", target_url);

    let session_id_header = req.headers().get("X-Session-ID").cloned();
    let user_id_header = req.headers().get("X-Authenticated-User-ID").cloned();
    let content_type_header = req.headers().get("Content-Type").cloned();

    let method = req.method().clone();
    let mut proxy_req = client.request(method, &target_url);

    if let Some(session_id) = session_id_header {
        proxy_req = proxy_req.header("X-Session-ID", session_id);
    }

    if let Some(user_id) = user_id_header {
        proxy_req = proxy_req.header("X-Authenticated-User-ID", user_id);
    }

    if let Some(content_type) = content_type_header {
        proxy_req = proxy_req.header("Content-Type", content_type);
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read request body: {:?}", e);
            (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
        })?;

    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes.to_vec());
    }

    let proxy_response = proxy_req
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Proxy request failed: {:?}", e);
            (StatusCode::BAD_GATEWAY, "Backend service unavailable").into_response()
        })?;

    let status = proxy_response.status();
    let headers = proxy_response.headers().clone();
    
    let body_bytes = proxy_response.bytes().await.map_err(|e| {
        tracing::error!("Failed to read proxy response body: {:?}", e);
        (StatusCode::BAD_GATEWAY, "Failed to read backend response").into_response()
    })?;

    let mut response = Response::builder().status(status);
    
    for (key, value) in headers.iter() {
        response = response.header(key, value);
    }
    
    response
        .body(Body::from(body_bytes))
        .map_err(|e| {
            tracing::error!("Failed to build response: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
        })
}

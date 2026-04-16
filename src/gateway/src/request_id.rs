// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// A request correlation ID propagated through all services.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Middleware that reads `X-Request-Id` from the incoming request or generates a new UUID.
/// The ID is inserted as a request extension (for downstream handlers/proxy) and set
/// as a response header.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let mut response = next.run(req).await;

    if let Ok(header_value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-request-id", header_value);
    }

    response
}

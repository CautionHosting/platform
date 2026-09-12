// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::Arc;

/// Simple per-IP rate limiter for webhook endpoints.
/// Allows `max_requests` per `window` duration per source IP.
#[derive(Clone)]
pub(crate) struct RateLimiter {
    requests: Arc<tokio::sync::Mutex<HashMap<String, Vec<std::time::Instant>>>>,
    max_requests: usize,
    window: std::time::Duration,
    max_entries: usize,
}

impl RateLimiter {
    pub(crate) fn new(max_requests: usize, window: std::time::Duration) -> Self {
        Self {
            requests: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max_requests,
            window,
            max_entries: 10_000,
        }
    }

    async fn check(&self, ip: &str) -> bool {
        let now = std::time::Instant::now();
        let mut map = self.requests.lock().await;

        // Evict stale entries to prevent unbounded growth
        if map.len() > self.max_entries {
            map.retain(|_, entries| {
                entries
                    .last()
                    .is_some_and(|t| now.duration_since(*t) < self.window)
            });
        }

        let entries = map.entry(ip.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() >= self.max_requests {
            return false;
        }
        entries.push(now);
        true
    }
}

/// Rate-limiting middleware for webhook routes.
///
/// `x-forwarded-for` is trustworthy here because metering is not reachable
/// directly from the internet — the gateway is the only caller and it
/// overwrites this header with the real peer IP (see
/// `gateway::proxy::metering_proxy_handler`), discarding whatever the original
/// client sent. Without that, this header would be client-controlled and every
/// caller could collapse into the same rate-limit bucket.
#[tracing::instrument(skip_all)]
pub(crate) async fn webhook_rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next_back())
        .unwrap_or("unknown")
        .trim()
        .to_string();

    if !limiter.check(&ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    next.run(req).await
}

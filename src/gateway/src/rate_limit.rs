// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Request, ConnectInfo, State},
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    async fn check_rate_limit(&self, ip: &str) -> bool {
        let mut state = self.state.write().await;
        let now = Instant::now();

        let entry = state.entry(ip.to_string()).or_insert((0, now));

        if now.duration_since(entry.1) >= self.window_duration {
            *entry = (1, now);
            return true;
        }

        entry.0 += 1;
        entry.0 <= self.max_requests
    }

    pub async fn cleanup_task(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut state = self.state.write().await;
            let now = Instant::now();

            state.retain(|_, (_, last_reset)| {
                now.duration_since(*last_reset) < self.window_duration
            });

            tracing::debug!("Rate limiter cleanup: {} active IPs", state.len());
        }
    }
}

pub async fn rate_limit_middleware(
    State(rate_limiter): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();

    if !rate_limiter.check_rate_limit(&ip).await {
        tracing::warn!("Rate limit exceeded for IP: {}", ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Please try again later.",
        )
            .into_response();
    }

    next.run(request).await
}

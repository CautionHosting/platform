// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// In-memory, per-process, sliding-window (best-effort) rate limiter keyed
/// by an arbitrary string (an IP, a username, etc).
///
/// IMPORTANT ASSUMPTION: state is a plain `HashMap` behind a `tokio::RwLock`
/// with NO cross-process or cross-host sharing. This is only correct when a
/// single gateway process/replica handles all traffic for its counters (true
/// today: one gateway per enclave). It resets on every process restart, and
/// if the gateway is ever scaled to multiple replicas behind a load
/// balancer, each replica gets its own independent budget — the effective
/// limit becomes `max_requests * replica_count`. Revisit with a shared store
/// (e.g. Redis) before going multi-replica.
#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window_duration: Duration,
}

/// Global per-IP budget applied as blanket middleware over all `/auth/*`
/// routes. See `main.rs`.
pub const GLOBAL_MAX_REQUESTS: u32 = 100;
pub const GLOBAL_WINDOW_SECS: u64 = 60;

/// Tighter per-IP budget on username-scoped `begin` requests
/// (`/auth/login/begin` and `/auth/qr-login/authenticate`, only when a
/// `username` is supplied). This is on top of the global 100/60s bucket and
/// exists because a scoped-begin request does more per-call work (a DB
/// lookup) than a plain broadcast begin, and is the request shape an
/// enumeration attacker actually wants to spam. Exceeding this bucket
/// returns a hard 429 — that's safe here because the check is keyed by IP,
/// not by username, so a 429 leaks nothing about any particular username's
/// existence.
pub const SCOPED_BEGIN_MAX_REQUESTS: u32 = 20;
pub const SCOPED_BEGIN_WINDOW_SECS: u64 = 60;

/// Per-username budget on scoped `begin` requests, keyed by the normalized
/// username rather than the caller's IP. Deliberately small: once a
/// username has been probed this many times in the window, EVERY further
/// scoped-begin request for that username is forced to the decoy shape
/// (see `handlers::scoped_or_decoy_challenge`) regardless of whether the
/// username is real, instead of returning a 429. A hard 429 here would (a)
/// let an attacker DoS a real user's login just by spamming their username,
/// and (b) itself leak that the username is being targeted. Forcing a decoy
/// keeps the response shape identical to a real challenge and caps how much
/// enumeration signal a sustained per-username probe can extract, while a
/// legitimate user still has the username-less discoverable/broadcast path
/// as an escape hatch.
pub const USERNAME_BEGIN_MAX_REQUESTS: u32 = 10;
pub const USERNAME_BEGIN_WINDOW_SECS: u64 = 60;

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    pub async fn check_rate_limit(&self, ip: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allows_requests_under_limit() {
        let limiter = RateLimiter::new(5, 60);

        for _ in 0..5 {
            assert!(limiter.check_rate_limit("192.168.1.1").await);
        }
    }

    #[tokio::test]
    async fn test_blocks_requests_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(!limiter.check_rate_limit("10.0.0.1").await);
        assert!(!limiter.check_rate_limit("10.0.0.1").await);
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let limiter = RateLimiter::new(2, 60);

        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(!limiter.check_rate_limit("10.0.0.1").await);

        // Different IP should have its own counter
        assert!(limiter.check_rate_limit("10.0.0.2").await);
        assert!(limiter.check_rate_limit("10.0.0.2").await);
        assert!(!limiter.check_rate_limit("10.0.0.2").await);
    }

    #[tokio::test]
    async fn test_window_reset() {
        // Use a 1-second window for fast testing
        let limiter = RateLimiter::new(2, 1);

        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(!limiter.check_rate_limit("10.0.0.1").await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Should be allowed again
        assert!(limiter.check_rate_limit("10.0.0.1").await);
    }

    #[tokio::test]
    async fn test_single_request_limit() {
        let limiter = RateLimiter::new(1, 60);

        assert!(limiter.check_rate_limit("10.0.0.1").await);
        assert!(!limiter.check_rate_limit("10.0.0.1").await);
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired() {
        let limiter = RateLimiter::new(100, 1);

        // Add some entries
        limiter.check_rate_limit("10.0.0.1").await;
        limiter.check_rate_limit("10.0.0.2").await;

        // Verify entries exist
        {
            let state = limiter.state.read().await;
            assert_eq!(state.len(), 2);
        }

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Manually trigger cleanup logic
        {
            let mut state = limiter.state.write().await;
            let now = Instant::now();
            state.retain(|_, (_, last_reset)| {
                now.duration_since(*last_reset) < limiter.window_duration
            });
        }

        // Entries should be cleaned up
        {
            let state = limiter.state.read().await;
            assert_eq!(state.len(), 0);
        }
    }

    #[tokio::test]
    async fn test_username_begin_limiter_trips_at_configured_budget() {
        // Exercises the actual constants item #3 wires into
        // `AppState::username_begin_limiter`, not just an arbitrary budget.
        let limiter = RateLimiter::new(USERNAME_BEGIN_MAX_REQUESTS, USERNAME_BEGIN_WINDOW_SECS);

        for _ in 0..USERNAME_BEGIN_MAX_REQUESTS {
            assert!(limiter.check_rate_limit("alice").await);
        }
        assert!(!limiter.check_rate_limit("alice").await);
    }

    #[tokio::test]
    async fn test_scoped_begin_limiter_trips_at_configured_budget() {
        let limiter = RateLimiter::new(SCOPED_BEGIN_MAX_REQUESTS, SCOPED_BEGIN_WINDOW_SECS);

        for _ in 0..SCOPED_BEGIN_MAX_REQUESTS {
            assert!(limiter.check_rate_limit("10.0.0.1").await);
        }
        assert!(!limiter.check_rate_limit("10.0.0.1").await);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let limiter = RateLimiter::new(100, 60);

        let mut handles = vec![];
        for i in 0..10 {
            let limiter = limiter.clone();
            let ip = format!("10.0.0.{}", i);
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    limiter.check_rate_limit(&ip).await;
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all IPs were tracked
        let state = limiter.state.read().await;
        assert_eq!(state.len(), 10);
    }
}

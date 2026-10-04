// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Sentry error reporting for Axum services.
//!
//! ## Architecture
//!
//! Two cooperating components handle per-request Sentry reporting with
//! correct breadcrumb isolation under a multi-threaded tokio runtime:
//!
//! 1. **`RequestBreadcrumbLayer`** (a `tracing_subscriber::Layer`) collects
//!    breadcrumbs from `tracing` events into a shared map keyed by request ID.
//!    It runs synchronously inside the tracing subscriber, so it always executes
//!    on the same thread as the event emission and writes to a `Send + Sync`
//!    data structure rather than a thread-local.
//!
//! 2. **`SentryLayer`** (a Tower layer) wraps each request. At request start
//!    it generates a request ID and stores it in a `tokio::task_local`. After
//!    the handler resolves, it drains that request's breadcrumbs from the map,
//!    creates a fresh per-request Sentry `Hub`, injects the breadcrumbs into
//!    the Hub's scope, and captures any attached error against that specific
//!    Hub. Because the Hub is held by reference (not resolved from a
//!    thread-local), this is correct regardless of which OS thread the task
//!    was rescheduled onto.
//!
//! ## Setup
//!
//! ```ignore
//! use tracing_subscriber::prelude::*;
//!
//! // 1. Initialize Sentry (keep the guard alive for the process lifetime)
//! let _sentry_guard = sentry_middleware::init_from_env();
//!
//! // 2. Build the subscriber stack
//! tracing_subscriber::registry()
//!     .with(tracing_subscriber::fmt::layer())
//!     .with(sentry::tracing::layer().event_filter(|_| {
//!         // Disable breadcrumb/event capture; we handle breadcrumbs ourselves.
//!         // Spans are still tracked for performance data.
//!         sentry_tracing::EventFilter::Ignore
//!     }))
//!     .with(sentry_middleware::RequestBreadcrumbLayer::new())
//!     .init();
//!
//! // 3. Add the Tower layer to your router
//! let app = router.layer(sentry_middleware::SentryLayer);
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sentry::{Breadcrumb, Hub};
use tower::{Layer, Service};
use tracing_subscriber::layer::{Context as SubContext, Layer as SubLayer};

// ---------------------------------------------------------------------------
// Task-local request ID
// ---------------------------------------------------------------------------

// The current request ID, set by [`SentryService`] for the duration of each
// request handler invocation.
//
// The [`RequestBreadcrumbLayer`] reads this to know which bucket to write
// breadcrumbs into.
tokio::task_local! {
    pub static REQUEST_ID: uuid::Uuid;
}

// ---------------------------------------------------------------------------
// Breadcrumb storage (shared across threads)
// ---------------------------------------------------------------------------

type BreadcrumbMap = Mutex<HashMap<uuid::Uuid, Vec<Breadcrumb>>>;

/// A global map from request ID to accumulated breadcrumbs.
///
/// Written by [`RequestBreadcrumbLayer`] (synchronously, on the emitting
/// thread) and read+removed by [`SentryService`] (after the handler resolves).
/// Using a `Mutex<HashMap>` is sufficient: the critical section is a single
/// `Vec::push` or `HashMap::remove`, both O(1) amortized.
static BREADCRUMBS: std::sync::LazyLock<BreadcrumbMap> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Maximum breadcrumbs stored per request. Mirrors Sentry's default
/// `max_breadcrumbs` of 100.
const MAX_BREADCRUMBS_PER_REQUEST: usize = 100;

// ---------------------------------------------------------------------------
// RequestBreadcrumbLayer (tracing subscriber layer)
// ---------------------------------------------------------------------------

/// A [`tracing_subscriber::Layer`] that collects breadcrumbs from `tracing`
/// events into the shared [`BREADCRUMBS`] map, keyed by the current request ID.
///
/// Events emitted outside of a request context (no active `REQUEST_ID`) are
/// silently dropped. This is correct: there is no request to attach them to.
#[derive(Debug, Clone, Default)]
pub struct RequestBreadcrumbLayer;

impl RequestBreadcrumbLayer {
    /// Create a new layer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> SubLayer<S> for RequestBreadcrumbLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: SubContext<'_, S>) {
        // Only collect breadcrumbs from info and warn level events.
        // Error-level events are captured as Sentry events by the Tower layer;
        // debug/trace are too noisy.
        let level = event.metadata().level();
        if !matches!(level, &tracing::Level::INFO | &tracing::Level::WARN) {
            return;
        }

        // Resolve the current request ID from the task-local.
        // If we're not inside a request (e.g. background task), skip.
        let Ok(request_id) = REQUEST_ID.try_with(|id| *id) else {
            return;
        };

        let breadcrumb = event_to_breadcrumb(event, level);

        let mut map = BREADCRUMBS.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(request_id).or_default();
        entry.push(breadcrumb);
        // Evict oldest if over the limit.
        if entry.len() > MAX_BREADCRUMBS_PER_REQUEST {
            let excess = entry.len() - MAX_BREADCRUMBS_PER_REQUEST;
            entry.drain(..excess);
        }
    }
}

/// Convert a `tracing` event into a Sentry [`Breadcrumb`].
fn event_to_breadcrumb(event: &tracing::Event<'_>, level: &tracing::Level) -> Breadcrumb {
    let mut visitor = BreadcrumbVisitor::default();
    event.record(&mut visitor);

    let category = event.metadata().target().to_string();
    let message = visitor.message.unwrap_or_default();

    let mut data = sentry::protocol::Map::new();
    for (key, value) in &visitor.fields {
        data.insert(key.clone(), value.clone().into());
    }

    Breadcrumb {
        ty: "log".into(),
        category: Some(category),
        level: match *level {
            tracing::Level::ERROR => sentry::Level::Error,
            tracing::Level::WARN => sentry::Level::Warning,
            tracing::Level::INFO => sentry::Level::Info,
            tracing::Level::DEBUG => sentry::Level::Debug,
            tracing::Level::TRACE => sentry::Level::Debug,
        },
        message: Some(message),
        data,
        ..Default::default()
    }
}

/// A `tracing` field visitor that collects string representations of all fields.
#[derive(Debug, Default)]
struct BreadcrumbVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for BreadcrumbVisitor {
    fn record_debug(&mut self, key: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let val = format!("{value:?}");
        if key.name() == "message" || key.name() == "_message" {
            self.message = Some(val.trim_matches('"').to_string());
        } else {
            self.fields.push((key.name().to_string(), val));
        }
    }

    fn record_str(&mut self, key: &tracing::field::Field, value: &str) {
        if key.name() == "message" || key.name() == "_message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push((key.name().to_string(), value.to_string()));
        }
    }

    fn record_i64(&mut self, key: &tracing::field::Field, value: i64) {
        self.fields.push((key.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, key: &tracing::field::Field, value: u64) {
        self.fields.push((key.name().to_string(), value.to_string()));
    }

    fn record_f64(&mut self, key: &tracing::field::Field, value: f64) {
        self.fields.push((key.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, key: &tracing::field::Field, value: bool) {
        self.fields.push((key.name().to_string(), value.to_string()));
    }

    fn record_error(&mut self, key: &tracing::field::Field, value: &(dyn std::error::Error + 'static)) {
        if key.name() == "message" || key.name() == "_message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push((key.name().to_string(), value.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// SentryReportable (response extension)
// ---------------------------------------------------------------------------

/// A boxed error attached to an HTTP response for centralized Sentry reporting.
///
/// Because `Arc<dyn Error + Send + Sync>` is not `Sized`, it cannot be used
/// directly as an [`axum::Extension`] type key. This newtype wrapper makes it
/// sized while preserving the trait object inside.
#[derive(Debug, Clone)]
pub struct SentryReportable(pub Arc<dyn std::error::Error + Send + Sync>);

// ---------------------------------------------------------------------------
// Init helper
// ---------------------------------------------------------------------------

/// Initialize Sentry from the `SENTRY_DSN` environment variable.
///
/// Returns the guard (which must be kept alive for the duration of the process)
/// if initialization succeeded, or `None` if `SENTRY_DSN` is unset or invalid.
#[tracing::instrument(skip_all)]
pub fn init_from_env() -> Option<sentry::ClientInitGuard> {
    if let Ok(dsn) = std::env::var("SENTRY_DSN") {
        let guard = sentry::init(sentry::ClientOptions::new().dsn(&dsn));
        tracing::info!("Sentry initialized");
        Some(guard)
    } else {
        tracing::warn!("SENTRY_DSN not set, Sentry reporting disabled");
        None
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Build an error response that carries a [`SentryReportable`] extension for
/// the [`SentryLayer`] to extract and report.
///
/// Use this in every `IntoResponse` impl so the error is reported centrally:
///
/// ```ignore
/// impl IntoResponse for MyError {
///     fn into_response(self) -> Response {
///         let (status, body) = match &self { /* ... */ };
///         sentry_middleware::error_response(status, body, self)
///     }
/// }
/// ```
#[tracing::instrument(skip_all)]
pub fn error_response<B: IntoResponse>(
    status: StatusCode,
    body: B,
    error: impl std::error::Error + Send + Sync + 'static,
) -> Response {
    let mut response = (status, body).into_response();
    response
        .extensions_mut()
        .insert(SentryReportable(Arc::new(error)));
    response
}

/// Attach a [`SentryReportable`] extension to an already-built [`Response`].
///
/// Use this when the response requires custom headers or a body type that
/// doesn't fit the simple `(status, body)` tuple pattern:
///
/// ```ignore
/// impl IntoResponse for MyError {
///     fn into_response(self) -> Response {
///         let response = (StatusCode::UNAUTHORIZED, headers, body).into_response();
///         sentry_middleware::attach(response, self)
///     }
/// }
/// ```
#[tracing::instrument(skip_all)]
pub fn attach(
    mut response: Response,
    error: impl std::error::Error + Send + Sync + 'static,
) -> Response {
    response
        .extensions_mut()
        .insert(SentryReportable(Arc::new(error)));
    response
}

// ---------------------------------------------------------------------------
// SentryLayer (Tower layer)
// ---------------------------------------------------------------------------

/// A Tower [`Layer`] that provides per-request Sentry error reporting with
/// isolated breadcrumbs.
///
/// For each request:
/// 1. Generates a unique request ID and stores it in the `REQUEST_ID` task-local.
/// 2. Calls the inner service (handler).
/// 3. After the response is produced, drains this request's breadcrumbs from
///    the shared map.
/// 4. If the response carries a [`SentryReportable`] and the status is 5xx,
///    creates a fresh per-request `Hub`, injects the breadcrumbs into its scope,
///    and captures the error against that Hub.
#[derive(Debug, Clone, Copy)]
pub struct SentryLayer;

impl<S> Layer<S> for SentryLayer {
    type Service = SentryService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SentryService { inner }
    }
}

/// The service produced by [`SentryLayer`].
#[derive(Clone)]
pub struct SentryService<S> {
    inner: S,
}

impl<S, ReqBody> Service<axum::http::Request<ReqBody>> for SentryService<S>
where
    S: Service<axum::http::Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            // Generate a unique request ID for breadcrumb correlation.
            let request_id = uuid::Uuid::new_v4();

            // Run the handler with REQUEST_ID set so the breadcrumb layer
            // knows where to write. `scope` returns a future that sets the
            // task-local for the duration of the inner future.
            let response = REQUEST_ID
                .scope(request_id, async { inner.call(req).await })
                .await?;

            let mut response = response;

            if let Some(SentryReportable(error)) =
                response.extensions_mut().remove::<SentryReportable>()
            {
                if response.status().is_server_error() {
                    // Drain breadcrumbs accumulated for this request.
                    let breadcrumbs = {
                        let mut map = BREADCRUMBS.lock().unwrap_or_else(|e| e.into_inner());
                        map.remove(&request_id).unwrap_or_default()
                    };

                    tracing::error!(
                        status = %response.status(),
                        error = %error,
                        breadcrumb_count = breadcrumbs.len(),
                        "Reporting error to Sentry"
                    );

                    // Create a per-request Hub so breadcrumbs are isolated
                    // from other concurrent requests. We hold the Hub by
                    // reference (Arc), so this is correct regardless of which
                    // OS thread we're on.
                    let hub = Arc::new(Hub::current());
                    for crumb in breadcrumbs {
                        hub.add_breadcrumb(crumb);
                    }
                    hub.capture_error(error.as_ref());
                } else {
                    // Clean up breadcrumbs even for non-error responses to
                    // avoid leaking memory.
                    let mut map = BREADCRUMBS.lock().unwrap_or_else(|e| e.into_inner());
                    map.remove(&request_id);

                    tracing::debug!(
                        status = %response.status(),
                        error = %error
                    );
                }
            } else {
                // No error attached; still clean up breadcrumbs.
                let mut map = BREADCRUMBS.lock().unwrap_or_else(|e| e.into_inner());
                map.remove(&request_id);
            }

            Ok(response)
        })
    }
}


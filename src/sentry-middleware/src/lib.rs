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
//!    creates a fresh per-request Sentry `Hub` (with an empty scope, reusing
//!    only the global client), injects the breadcrumbs into that Hub's scope,
//!    and captures any attached error against it. Because the Hub is a new
//!    instance rather than the thread-local one, state never leaks across
//!    concurrent requests regardless of OS-thread scheduling.
//!
//! Each service reads its own DSN from `SENTRY_DSN_<SERVICE>`, so different
//! applications can report to different Sentry projects (for example
//! `SENTRY_DSN_API`, `SENTRY_DSN_GATEWAY`, `SENTRY_DSN_METERING`). A service
//! whose variable is unset simply does not report.
//!
//! ## Setup
//!
//! ```ignore
//! use tracing_subscriber::prelude::*;
//!
//! // 1. Initialize Sentry (keep the guard alive for the process lifetime)
//! let _sentry_guard = sentry_middleware::init_sentry!();
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
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use sentry::{Breadcrumb, Hub, Scope};
use tower::{Layer, Service};
use tracing_subscriber::layer::{Context as SubContext, Layer as SubLayer};

mod privacy;

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

/// The service name supplied to [`init_from_env`], used as the `service_name`
/// tag on reported events.
///
/// Set once at startup. It stays `None` if [`init_from_env`] was never called,
/// but in that case Sentry is not initialized and nothing is reported anyway.
static SERVICE_NAME: OnceLock<String> = OnceLock::new();

/// The service name registered by [`init_from_env`], if any.
fn service_name() -> Option<&'static str> {
    SERVICE_NAME.get().map(String::as_str)
}

// ---------------------------------------------------------------------------
// RequestBreadcrumbLayer (tracing subscriber layer)
// ---------------------------------------------------------------------------

/// A [`tracing_subscriber::Layer`] that collects breadcrumbs from `tracing`
/// events into the shared [`BREADCRUMBS`] map, keyed by the current request ID.
///
/// Every level except `debug` and `trace` becomes a breadcrumb, so error events
/// are included and a failing request carries its own error logs in its Sentry
/// trail. Debug and trace are dropped as too noisy.
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
        // Collect breadcrumbs from every level except debug and trace, which are
        // too noisy. Error events are included so the failing request's own
        // error logs appear in its trail.
        //
        // The Sentry layer's own "Reporting error to Sentry" event is emitted
        // after the request scope ends and after this request's breadcrumbs are
        // drained, so it never reaches this layer as a breadcrumb.
        let level = event.metadata().level();
        if matches!(level, &tracing::Level::DEBUG | &tracing::Level::TRACE) {
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
            self.fields
                .push((key.name().to_string(), value.to_string()));
        }
    }

    fn record_i64(&mut self, key: &tracing::field::Field, value: i64) {
        self.fields
            .push((key.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, key: &tracing::field::Field, value: u64) {
        self.fields
            .push((key.name().to_string(), value.to_string()));
    }

    fn record_f64(&mut self, key: &tracing::field::Field, value: f64) {
        self.fields
            .push((key.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, key: &tracing::field::Field, value: bool) {
        self.fields
            .push((key.name().to_string(), value.to_string()));
    }

    fn record_error(
        &mut self,
        key: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        if key.name() == "message" || key.name() == "_message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .push((key.name().to_string(), value.to_string()));
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

/// Environment variable name holding the Sentry DSN for `service`.
///
/// The convention is `SENTRY_DSN_<SERVICE>`, where `<SERVICE>` is the service
/// name with ASCII letters upper-cased and every non-alphanumeric character
/// replaced by `_`. For example, `"api"` yields `SENTRY_DSN_API` and
/// `"email-service"` yields `SENTRY_DSN_EMAIL_SERVICE`.
#[must_use]
pub fn dsn_env_var(service: &str) -> String {
    let suffix: String = service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("SENTRY_DSN_{suffix}")
}

/// Initialize Sentry from this service's `SENTRY_DSN_<SERVICE>` environment
/// variable.
///
/// Returns the guard (which must be kept alive for the duration of the process)
/// if initialization succeeded, or `None` if the variable is unset or invalid.
/// See [`dsn_env_var`] for how `service` maps to the variable name.
///
/// The Sentry environment is taken from the `ENVIRONMENT` variable when set, so
/// Sentry agrees with the services' own production guards. When it is unset,
/// Sentry's built-in default (`development`/`production`) applies.
///
/// Prefer the [`init_sentry!`] macro, which supplies the calling crate's name
/// automatically.
#[tracing::instrument(skip_all, fields(service = %service))]
pub fn init_from_env(service: &str) -> Option<sentry::ClientInitGuard> {
    let _ = SERVICE_NAME.set(service.to_string());

    let env_var = dsn_env_var(service);
    if let Ok(dsn) = std::env::var(&env_var) {
        let guard = sentry::init(client_options(&dsn));
        tracing::info!(env_var = %env_var, "Sentry initialized");
        Some(guard)
    } else {
        tracing::warn!(env_var = %env_var, "Sentry DSN not set, Sentry reporting disabled");
        None
    }
}

fn client_options(dsn: &str) -> sentry::ClientOptions {
    let mut options = sentry::ClientOptions::new()
        .dsn(dsn)
        .send_default_pii(false)
        .before_send(privacy::scrub_event);
    if let Some(environment) = environment_from_env() {
        options = options.environment(environment);
    }
    options
}

/// The Sentry environment, taken from the `ENVIRONMENT` variable.
///
/// Unset or blank leaves Sentry's own default in place.
fn environment_from_env() -> Option<String> {
    std::env::var("ENVIRONMENT")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Initialize Sentry for the calling crate.
///
/// The `env!` call expands in the caller's crate, so `CARGO_PKG_NAME` resolves
/// to that crate's package name and `init_sentry!()` reads its own
/// `SENTRY_DSN_<SERVICE>` variable without the name being hardcoded:
///
/// ```ignore
/// let _sentry_guard = sentry_middleware::init_sentry!();
/// ```
///
/// Pass an explicit name to override, for example `init_sentry!("worker")`.
#[macro_export]
macro_rules! init_sentry {
    () => {
        $crate::init_from_env(env!("CARGO_PKG_NAME"))
    };
    ($service:expr) => {
        $crate::init_from_env($service)
    };
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
// Spawned-task helpers (for long-running work that outlives the response)
// ---------------------------------------------------------------------------

/// Drains and removes all breadcrumbs accumulated for `request_id` from the
/// shared map. Returns an empty vec if none exist.
///
/// Use this in a spawned task's error path to collect breadcrumbs before
/// reporting to Sentry via [`capture_error_with_breadcrumbs`].
#[tracing::instrument(skip_all)]
pub fn drain_breadcrumbs(request_id: &uuid::Uuid) -> Vec<Breadcrumb> {
    let mut map = BREADCRUMBS.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(request_id).unwrap_or_default()
}

/// Captures an error to Sentry with the given breadcrumbs attached, using a
/// fresh isolated Hub (global client, minimal scope).
///
/// This is the entry point for reporting errors from spawned tasks that
/// outlive the HTTP response (e.g. deploy workers). Such tasks have no request
/// metadata, so the only tag attached is `service_name`.
#[tracing::instrument(skip_all)]
pub fn capture_error_with_breadcrumbs(
    error: &(impl std::error::Error + Send + Sync),
    breadcrumbs: Vec<Breadcrumb>,
) {
    let client = Hub::main().client();
    let mut scope = Scope::default();
    if let Some(service) = service_name() {
        scope.set_tag("service_name", service);
    }
    for (index, location) in error_locations(error) {
        scope.set_tag(format!("error.location.{index}").as_str(), location);
    }
    let hub = Arc::new(Hub::new(client, Arc::new(scope)));
    for crumb in breadcrumbs {
        hub.add_breadcrumb(crumb);
    }
    hub.capture_error(error);
}

// ---------------------------------------------------------------------------
// SentryLayer (Tower layer)
// ---------------------------------------------------------------------------

/// Build the isolated scope used for a reported request error.
///
/// Tags the event with the request method, path (never the query string), status
/// code, the per-request ID, and the service name when one is registered.
fn request_scope(method: &Method, path: &str, status: StatusCode, request_id: uuid::Uuid) -> Scope {
    let mut scope = Scope::default();
    scope.set_tag("http.method", method.as_str());
    scope.set_tag("http.path", path);
    scope.set_tag("http.status_code", status.as_u16());
    scope.set_tag("request_id", request_id);
    if let Some(service) = service_name() {
        scope.set_tag("service_name", service);
    }
    scope
}

/// Extract the code location from an error's `Display` output.
///
/// The dterror convention renders every message as `... [{location}]`, where
/// [`Location`] displays as `file:line:column`, so the location is the text
/// inside the final bracket pair. Returns `None` when the message does not end
/// with a bracketed location.
///
/// [`Location`]: std::panic::Location
fn error_location(display: &str) -> Option<&str> {
    let inner = display.trim_end().strip_suffix(']')?;
    let start = inner.rfind('[')?;
    let location = inner[start + 1..].trim();
    // A location always carries `file:line:column`, so require a colon. This
    // keeps unrelated bracketed suffixes from being mistaken for one.
    if location.is_empty() || !location.contains(':') {
        return None;
    }
    Some(location)
}

/// Collect the code location of every error in a source chain.
///
/// Returns `(index, location)` pairs in the same order Sentry presents the
/// chained exceptions, outermost first: index `0` is the error passed in (the
/// one Sentry shows first), index `1` its first source, and so on. Frames whose
/// `Display` has no bracketed location are omitted, but indices stay absolute so
/// they still identify the frame's position in the chain.
fn error_locations<E>(error: &E) -> Vec<(usize, String)>
where
    E: std::error::Error + ?Sized,
{
    let mut locations = Vec::new();

    if let Some(location) = error_location(&error.to_string()) {
        locations.push((0, location.to_string()));
    }

    let mut index = 1;
    let mut current = error.source();
    while let Some(source) = current {
        if let Some(location) = error_location(&source.to_string()) {
            locations.push((index, location.to_string()));
        }
        current = source.source();
        index += 1;
    }

    locations
}

/// A Tower [`Layer`] that provides per-request Sentry error reporting with
/// isolated breadcrumbs.
///
/// For each request:
/// 1. Generates a unique request ID and stores it in the `REQUEST_ID` task-local.
/// 2. Calls the inner service (handler).
/// 3. After the response is produced, drains this request's breadcrumbs from
///    the shared map.
/// 4. If the response carries a [`SentryReportable`] and the status is 5xx,
///    creates a fresh per-request `Hub` tagged with `http.method`, `http.path`
///    (path only, never the query string), `http.status_code`, `request_id`,
///    and `service_name`, plus `error.location.{i}` for every frame in the
///    error's source chain that has a bracketed location (index 0 is the error
///    itself, index 1 its first source, and so on), injects the breadcrumbs into
///    its scope, and captures the error against that Hub.
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

    #[tracing::instrument(skip_all)]
    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            // Generate a unique request ID for breadcrumb correlation.
            let request_id = uuid::Uuid::new_v4();

            // Capture request metadata before the request is moved into the
            // handler, so it can tag any error that gets reported. Only the
            // path is kept, never the query string.
            let method = req.method().clone();
            let path = req.uri().path().to_owned();

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

                    // Create a fresh per-request Hub so breadcrumbs and tags are
                    // fully isolated from other concurrent requests. We reuse the
                    // main hub's client (which carries release, environment, DSN)
                    // but start from a scope holding only this request's tags, so
                    // no state leaks across requests or users.
                    let client = Hub::main().client();
                    let mut scope = request_scope(&method, &path, response.status(), request_id);
                    for (index, location) in error_locations(error.as_ref()) {
                        scope.set_tag(format!("error.location.{index}").as_str(), location);
                    }
                    let hub = Arc::new(Hub::new(client, Arc::new(scope)));
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

#[cfg(test)]
mod tests {
    use super::{
        REQUEST_ID, RequestBreadcrumbLayer, drain_breadcrumbs, dsn_env_var, request_scope,
    };

    #[test]
    fn dsn_env_var_uppercases_simple_names() {
        assert_eq!(dsn_env_var("api"), "SENTRY_DSN_API");
        assert_eq!(dsn_env_var("gateway"), "SENTRY_DSN_GATEWAY");
        assert_eq!(dsn_env_var("metering"), "SENTRY_DSN_METERING");
    }

    #[test]
    fn dsn_env_var_replaces_non_alphanumerics_with_underscores() {
        assert_eq!(dsn_env_var("email-service"), "SENTRY_DSN_EMAIL_SERVICE");
        assert_eq!(dsn_env_var("a.b c"), "SENTRY_DSN_A_B_C");
    }

    #[test]
    fn dsn_env_var_handles_empty_service() {
        assert_eq!(dsn_env_var(""), "SENTRY_DSN_");
    }

    #[test]
    fn collects_every_level_but_debug_and_trace() {
        use tracing_subscriber::prelude::*;

        let subscriber = tracing_subscriber::registry().with(RequestBreadcrumbLayer::new());
        let request_id = uuid::Uuid::new_v4();

        tracing::subscriber::with_default(subscriber, || {
            REQUEST_ID.sync_scope(request_id, || {
                tracing::trace!(stage = "trace", "noise");
                tracing::debug!(stage = "debug", "noise");
                tracing::info!(stage = "prepare", payload_bytes = 128u64, "prepared");
                tracing::warn!(stage = "validate", attempts = 2u64, "retrying");
                tracing::error!(stage = "dispatch", "failed");
            });
        });

        let crumbs = drain_breadcrumbs(&request_id);
        assert_eq!(
            crumbs.len(),
            3,
            "debug and trace are dropped; info, warn and error are kept"
        );

        assert_eq!(crumbs[0].level, sentry::Level::Info);
        assert_eq!(crumbs[0].message.as_deref(), Some("prepared"));
        assert_eq!(
            crumbs[0].data.get("stage").and_then(|value| value.as_str()),
            Some("prepare")
        );

        assert_eq!(crumbs[1].level, sentry::Level::Warning);
        assert_eq!(crumbs[1].message.as_deref(), Some("retrying"));

        assert_eq!(crumbs[2].level, sentry::Level::Error);
        assert_eq!(crumbs[2].message.as_deref(), Some("failed"));
    }

    #[test]
    fn request_scope_tags_the_event() {
        use axum::http::{Method, StatusCode};

        // Register the service name for this test process. Harmless if another
        // test already set it, since the value is identical.
        let _ = super::SERVICE_NAME.set("test-service".to_string());

        let event = request_scope(
            &Method::GET,
            "/test/force-error",
            StatusCode::INTERNAL_SERVER_ERROR,
            uuid::Uuid::nil(),
        )
        .apply_to_event(sentry::protocol::Event::default())
        .expect("the scope always applies to an event");

        let tag = |key: &str| event.tags.get(key).map(String::as_str);
        assert_eq!(tag("http.method"), Some("GET"));
        assert_eq!(tag("http.path"), Some("/test/force-error"));
        assert_eq!(tag("http.status_code"), Some("500"));
        assert_eq!(
            tag("request_id"),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(tag("service_name"), Some("test-service"));
    }

    #[test]
    fn error_location_extracts_the_trailing_bracket() {
        assert_eq!(
            super::error_location("boom [/src/x.rs:12:3]"),
            Some("/src/x.rs:12:3")
        );
        assert_eq!(
            super::error_location("boom [/src/x.rs:12:3]\n"),
            Some("/src/x.rs:12:3")
        );
        assert_eq!(super::error_location("boom [file.rs:1]"), Some("file.rs:1"));
        assert_eq!(
            super::error_location("has [nested] and [/a.rs:1:1]"),
            Some("/a.rs:1:1")
        );
    }

    #[test]
    fn error_location_rejects_non_locations() {
        assert_eq!(super::error_location("boom"), None);
        assert_eq!(super::error_location("boom []"), None);
        assert_eq!(super::error_location("boom [WARN]"), None);
        assert_eq!(super::error_location("boom [still no colon]"), None);
    }

    #[derive(Debug)]
    struct OuterError {
        source: InnerError,
    }

    impl std::fmt::Display for OuterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "outer failed [src/outer.rs:1:2]")
        }
    }

    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    #[derive(Debug)]
    struct InnerError;

    impl std::fmt::Display for InnerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "inner failed [src/inner.rs:3:4]")
        }
    }

    impl std::error::Error for InnerError {}

    #[derive(Debug)]
    struct NoLocationError;

    impl std::fmt::Display for NoLocationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "no bracketed location here")
        }
    }

    impl std::error::Error for NoLocationError {}

    #[test]
    fn error_locations_walk_the_whole_source_chain() {
        let error = OuterError { source: InnerError };

        assert_eq!(
            super::error_locations(&error),
            vec![
                (0, "src/outer.rs:1:2".to_string()),
                (1, "src/inner.rs:3:4".to_string()),
            ]
        );
    }

    #[test]
    fn error_locations_keep_absolute_indices_when_a_frame_has_none() {
        #[derive(Debug)]
        struct WrappingError {
            source: NoLocationError,
        }

        impl std::fmt::Display for WrappingError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "wrapper failed [src/wrapper.rs:5:6]")
            }
        }

        impl std::error::Error for WrappingError {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.source)
            }
        }

        let error = WrappingError {
            source: NoLocationError,
        };

        // The source frame at index 1 has no location, so it is omitted, but
        // the surviving entry keeps index 0 rather than renumbering.
        assert_eq!(
            super::error_locations(&error),
            vec![(0, "src/wrapper.rs:5:6".to_string())]
        );
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sentry::protocol::{Context, Event, Stacktrace, Url, Value};

const REDACTED: &str = "[Filtered]";

/// Last-line defense for known diagnostic surfaces, not arbitrary secret detection.
/// Keep exception types, source locations, status codes and breadcrumb categories.
/// Source callers must still avoid putting opaque secrets in free-form messages.
pub(crate) fn scrub_event(mut event: Event<'static>) -> Option<Event<'static>> {
    for message in event.message.iter_mut() {
        *message = scrub_urls(message);
    }
    for exception in &mut event.exception.values {
        for message in exception.value.iter_mut() {
            *message = scrub_urls(message);
        }
        if let Some(mechanism) = &mut exception.mechanism {
            scrub_fields(&mut mechanism.data);
        }
        scrub_stacktrace(exception.stacktrace.as_mut());
    }
    scrub_stacktrace(event.stacktrace.as_mut());
    for thread in &mut event.threads.values {
        scrub_stacktrace(thread.stacktrace.as_mut());
    }
    for breadcrumb in &mut event.breadcrumbs.values {
        for message in breadcrumb.message.iter_mut() {
            *message = scrub_urls(message);
        }
        scrub_fields(&mut breadcrumb.data);
    }
    if let Some(logentry) = &mut event.logentry {
        logentry.message = scrub_urls(&logentry.message);
        for param in &mut logentry.params {
            scrub_value("", param);
        }
    }
    scrub_fields(&mut event.extra);
    for (name, value) in &mut event.tags {
        scrub_field_text(name, value);
    }
    for context in event.contexts.values_mut() {
        match context {
            Context::Other(data) => scrub_fields(data),
            Context::Response(response) => {
                response.data = None;
                response.cookies = None;
                for (name, value) in &mut response.headers {
                    scrub_field_text(name, value);
                }
            }
            Context::Trace(trace) => {
                for description in trace.description.iter_mut() {
                    *description = scrub_urls(description);
                }
                scrub_fields(&mut trace.data);
            }
            _ => {}
        }
    }
    if let Some(request) = &mut event.request {
        if let Some(url) = &mut request.url {
            scrub_url(url);
        }
        request.data = None;
        request.query_string = None;
        request.cookies = None;
        request.env.clear();
        for (name, value) in &mut request.headers {
            scrub_field_text(name, value);
        }
    }
    event.user = None;
    Some(event)
}

fn scrub_stacktrace(stacktrace: Option<&mut Stacktrace>) {
    if let Some(stacktrace) = stacktrace {
        for frame in &mut stacktrace.frames {
            scrub_fields(&mut frame.vars);
        }
    }
}

fn sensitive_field(name: &str) -> bool {
    let name: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    [
        "authorization",
        "cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "credential",
    ]
    .iter()
    .any(|part| name.contains(part))
        || name.ends_with("body")
        || name.ends_with("headers")
        || matches!(name.as_str(), "payload" | "bodytext" | "querystring")
}

fn scrub_field_text(name: &str, text: &mut String) {
    *text = if sensitive_field(name) {
        REDACTED.into()
    } else {
        scrub_urls(text)
    };
}

fn scrub_fields<'a>(fields: impl IntoIterator<Item = (&'a String, &'a mut Value)>) {
    for (name, value) in fields {
        scrub_value(name, value);
    }
}

fn scrub_value(name: &str, value: &mut Value) {
    if sensitive_field(name) {
        *value = REDACTED.into();
        return;
    }
    match value {
        Value::String(text) => *text = scrub_urls(text),
        Value::Array(values) => {
            for value in values {
                scrub_value("", value);
            }
        }
        Value::Object(fields) => scrub_fields(fields),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn scrub_url(url: &mut Url) {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
}

/// Strip URL userinfo, all queries (not just named tokens), and fragments.
/// Ambiguous spans containing multiple URLs are fully redacted.
/// Non-URL text, including error categories and bracketed locations, is retained.
fn scrub_urls(mut text: &str) -> String {
    let mut clean = String::with_capacity(text.len());
    while let Some(separator) = text.find("://") {
        let start = text[..separator]
            .char_indices()
            .rev()
            .find(|(_, c)| !c.is_ascii_alphanumeric() && !matches!(c, '+' | '-' | '.'))
            .map_or(0, |(index, c)| index + c.len_utf8());
        // Quotes can occur inside userinfo or query values. Splitting there
        // would scrub only the URL prefix and leave the secret suffix intact.
        let end = text[separator + 3..]
            .find(char::is_whitespace)
            .map_or(text.len(), |index| separator + 3 + index);
        let end = text[..end]
            .trim_end_matches([')', ',', ';', '\"', '\'', '>'])
            .len();
        clean.push_str(&text[..start]);
        match Url::parse(&text[start..end]) {
            Ok(mut url) if !text[separator + 3..end].contains("://") => {
                scrub_url(&mut url);
                clean.push_str(url.as_str());
            }
            _ => clean.push_str(REDACTED),
        }
        text = &text[end..];
    }
    clean.push_str(text);
    clean
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use sentry::{Hub, protocol::Event};
    use tower::{Layer, Service};
    use tracing_subscriber::prelude::*;

    #[derive(Default)]
    struct OfflineTransport(Mutex<Vec<sentry::Envelope>>);

    impl sentry::Transport for OfflineTransport {
        fn send_envelope(&self, envelope: sentry::Envelope) {
            self.0.lock().unwrap().push(envelope);
        }
    }

    fn offline_client() -> (Arc<sentry::Client>, Arc<OfflineTransport>) {
        let transport = Arc::new(OfflineTransport::default());
        let options =
            crate::client_options("https://public@sentry.invalid/1").transport(transport.clone());
        assert!(!options.send_default_pii);
        (Arc::new(sentry::Client::from(options)), transport)
    }

    fn captured(transport: &OfflineTransport) -> (Vec<Event<'static>>, String) {
        let envelopes = transport.0.lock().unwrap();
        let mut bytes = Vec::new();
        for envelope in envelopes.iter() {
            envelope.to_writer(&mut bytes).unwrap();
        }
        (
            envelopes
                .iter()
                .filter_map(|e| e.event().cloned())
                .collect(),
            String::from_utf8(bytes).unwrap(),
        )
    }

    #[test]
    fn configured_capture_scrubs_structured_data_without_losing_context() {
        use sentry::protocol::{Value, value::from_value};

        let (client, transport) = offline_client();
        let hub = Hub::new(Some(client), Arc::new(sentry::Scope::default()));
        let event: Event = from_value(r#"{
            "message": "upstream rejected https://message-user:message-pass@host.invalid/v1?token=message-token [api.rs:4:2]",
            "logentry": {"message": "calling %s", "params": ["https://log-user:log-pass@host.invalid/v1?key=log-token", {"password": "log-secret"}]},
            "tags": {"http.status_code": "502", "api_key": "tag-secret", "endpoint": "https://host.invalid/v1?token=tag-token"},
            "extra": {"status": 502, "body_bytes": 99, "nested": [{"Access-Token": "extra-secret", "credentials": {"username": "credential-secret"}, "request_body": "body-secret", "endpoint": "https://host.invalid/v1?token=extra-token"}]},
            "contexts": {"upstream": {"type": "unknown", "status_code": 502, "response_body": "context-secret"}},
            "request": {"method": "POST", "url": "https://request-user:request-pass@host.invalid/v1?token=request-token#request-fragment", "query_string": "token=query-data-secret", "data": "request-data-secret", "cookies": "session=cookie-secret", "headers": {"Authorization": "Bearer auth-secret", "Proxy-Authorization": "proxy-secret", "Cookie": "header-cookie-secret", "X-API-Key": "header-key-secret", "Content-Type": "application/json"}, "env": {"PASSWORD": "env-secret"}},
            "user": {"email": "personal-secret@example.invalid"},
            "breadcrumbs": {"values": [{"category": "billing::request", "type": "http", "message": "request failed", "data": {"status_code": 502, "body_bytes": 99, "Authorization": "breadcrumb-auth-secret", "headers": "opaque-headers-secret", "body": "breadcrumb-body-secret", "payload": "payload-secret", "refreshToken": "refresh-secret", "url": "https://host.invalid/v1?token=breadcrumb-url-secret"}}]}
        }"#.parse::<Value>().unwrap()).unwrap();
        hub.capture_event(event);
        let (events, wire) = captured(&transport);
        assert_eq!(events.len(), 1);
        for secret in [
            "message-user",
            "message-pass",
            "message-token",
            "log-user",
            "log-pass",
            "log-token",
            "log-secret",
            "tag-secret",
            "tag-token",
            "extra-secret",
            "credential-secret",
            "body-secret",
            "extra-token",
            "context-secret",
            "request-user",
            "request-pass",
            "request-token",
            "request-fragment",
            "query-data-secret",
            "request-data-secret",
            "cookie-secret",
            "auth-secret",
            "proxy-secret",
            "header-key-secret",
            "env-secret",
            "personal-secret",
            "opaque-headers-secret",
            "payload-secret",
            "refresh-secret",
            "breadcrumb-url-secret",
        ] {
            assert!(!wire.contains(secret), "outgoing envelope leaked {secret}");
        }
        let event = &events[0];
        assert_eq!(
            event.message.as_deref(),
            Some("upstream rejected https://host.invalid/v1 [api.rs:4:2]")
        );
        assert_eq!(event.tags["http.status_code"], "502");
        assert_eq!(event.extra["status"].as_u64(), Some(502));
        assert_eq!(event.extra["body_bytes"].as_u64(), Some(99));
        let request = event.request.as_ref().unwrap();
        assert_eq!(request.method.as_deref(), Some("POST"));
        assert_eq!(
            request.url.as_ref().unwrap().as_str(),
            "https://host.invalid/v1"
        );
        assert_eq!(request.headers["Content-Type"], "application/json");
        let crumb = &event.breadcrumbs[0];
        assert_eq!(crumb.category.as_deref(), Some("billing::request"));
        assert_eq!(crumb.ty, "http");
        assert_eq!(crumb.message.as_deref(), Some("request failed"));
        assert_eq!(crumb.data["status_code"].as_u64(), Some(502));
        assert_eq!(crumb.data["body_bytes"].as_u64(), Some(99));
        assert!(
            matches!(&event.contexts["upstream"], sentry::protocol::Context::Other(data) if data["status_code"].as_u64() == Some(502))
        );
    }

    #[test]
    fn configured_capture_scrubs_sdk_contexts_and_frame_variables() {
        use sentry::protocol::{Context, Value, value::from_value};
        let (client, transport) = offline_client();
        let hub = Hub::new(Some(client), Arc::new(sentry::Scope::default()));
        let event: Event = from_value(r#"{
            "contexts": {
                "response": {"type": "response", "status_code": 502, "body_size": 99, "data": "response-secret", "cookies": "cookie-secret", "headers": {"Set-Cookie": "set-cookie-secret", "Content-Type": "text/plain"}},
                "trace": {"type": "trace", "op": "http.client", "description": "GET https://host.invalid/v1?token=trace-token", "data": {"api_key": "trace-secret", "status_code": 502}}
            },
            "exception": {"values": [{"type": "UpstreamError", "value": "upstream failed [upstream.rs:12:3]", "mechanism": {"type": "generic", "data": {"password": "mechanism-secret"}}, "stacktrace": {"frames": [{"filename": "upstream.rs", "lineno": 12, "colno": 3, "vars": {"authorization": "frame-secret", "attempt": 2}}]}}]},
            "stacktrace": {"frames": [{"filename": "worker.rs", "vars": {"api_key": "stack-secret"}}]},
            "threads": {"values": [{"stacktrace": {"frames": [{"filename": "worker.rs", "vars": {"token": "thread-secret"}}]}}]}
        }"#.parse::<Value>().unwrap()).unwrap();
        hub.capture_event(event);
        let (events, wire) = captured(&transport);
        assert_eq!(events.len(), 1);
        for secret in [
            "response-secret",
            "cookie-secret",
            "trace-token",
            "trace-secret",
            "mechanism-secret",
            "frame-secret",
            "stack-secret",
            "thread-secret",
        ] {
            assert!(!wire.contains(secret), "outgoing envelope leaked {secret}");
        }
        let event = &events[0];
        assert!(
            matches!(&event.contexts["response"], Context::Response(data) if data.status_code == Some(502) && data.body_size == Some(99) && data.headers["Content-Type"] == "text/plain")
        );
        assert!(
            matches!(&event.contexts["trace"], Context::Trace(data) if data.op.as_deref() == Some("http.client") && data.data["status_code"].as_u64() == Some(502))
        );
        let exception = &event.exception[0];
        assert_eq!(exception.ty, "UpstreamError");
        assert_eq!(
            exception.value.as_deref(),
            Some("upstream failed [upstream.rs:12:3]")
        );
        let frame = &exception.stacktrace.as_ref().unwrap().frames[0];
        assert_eq!(frame.filename.as_deref(), Some("upstream.rs"));
        assert_eq!(frame.lineno, Some(12));
        assert_eq!(frame.colno, Some(3));
        assert_eq!(frame.vars["attempt"].as_u64(), Some(2));
    }

    #[test]
    fn configured_capture_handles_url_boundaries_without_dropping_messages() {
        let (client, transport) = offline_client();
        let hub = Hub::new(Some(client), Arc::new(sentry::Scope::default()));
        let cases = [
            (
                "failed https://user:part)password@host.invalid/v1?key=query-secret [x.rs:1:2]",
                "failed https://host.invalid/v1 [x.rs:1:2]",
            ),
            (
                "failed https://user:part'password@host.invalid/v1?token=query-secret [x.rs:1:2]",
                "failed https://host.invalid/v1 [x.rs:1:2]",
            ),
            (
                "failed https://host.invalid/v1?token=prefix'query-secret [x.rs:1:2]",
                "failed https://host.invalid/v1 [x.rs:1:2]",
            ),
            (
                "https://upstream.invalid/o'brien?token=SYNTHETIC_SECRET",
                "https://upstream.invalid/o'brien",
            ),
            (
                "https://user:pre'SYNTHETIC_PASSWORD@host.invalid/v1?key=SYNTHETIC_SECRET",
                "https://host.invalid/v1",
            ),
            (
                "failed 'https://public.invalid/v1','https://user:SYNTHETIC_PASSWORD@host.invalid/v1'",
                "failed '[Filtered]'",
            ),
            (
                "UpstreamError: failed \"https://public.invalid/v1\",\"https://user:SYNTHETIC_PASSWORD@host.invalid/v1\" [x.rs:1:2]",
                "UpstreamError: failed \"[Filtered]\" [x.rs:1:2]",
            ),
            ("", ""),
            ("plain failure [x.rs:1:2]", "plain failure [x.rs:1:2]"),
            (
                "échec—url=HTTPS://user:password@[::1]:8080/v1?%74oken=query-secret",
                "échec—url=https://[::1]:8080/v1",
            ),
            (
                "GET (https://host.invalid/v1?token=one) then 'postgres://user:password@db.invalid/app?password=two'",
                "GET (https://host.invalid/v1) then 'postgres://db.invalid/app'",
            ),
            (
                "bad https://user:password@?token=query-secret [x.rs:1:2]",
                "bad [Filtered] [x.rs:1:2]",
            ),
        ];
        for (input, _) in cases {
            hub.capture_event(Event {
                message: Some(input.into()),
                ..Default::default()
            });
        }
        let (events, wire) = captured(&transport);
        assert_eq!(events.len(), cases.len());
        for secret in ["SYNTHETIC_SECRET", "SYNTHETIC_PASSWORD"] {
            assert!(!wire.contains(secret), "outgoing envelope leaked {secret}");
        }
        for (event, (_, expected)) in events.iter().zip(cases) {
            assert_eq!(event.message.as_deref(), Some(expected));
        }
    }

    #[derive(Debug)]
    struct UpstreamError;

    impl std::fmt::Display for UpstreamError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "upstream 502 for https://url-user:url-password@upstream.invalid/v1?access_token=query-secret#fragment-secret [src/upstream.rs:12:3]"
            )
        }
    }

    impl std::error::Error for UpstreamError {}

    #[derive(Debug)]
    struct DeployError(UpstreamError);

    impl std::fmt::Display for DeployError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "deployment failed [src/deploy.rs:20:5]")
        }
    }

    impl std::error::Error for DeployError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    struct MainClientGuard(Option<Arc<sentry::Client>>);

    impl Drop for MainClientGuard {
        fn drop(&mut self) {
            Hub::main().bind_client(self.0.take());
        }
    }

    #[tokio::test]
    async fn configured_capture_scrubs_request_and_background_url_secrets() {
        let (client, transport) = offline_client();
        let _restore = MainClientGuard(Hub::main().client());
        Hub::main().bind_client(Some(client));
        let app = axum::Router::new().route("/deploy", axum::routing::get(|| async {
            tracing::error!(target: "deploy::upstream", status = 502u64,
                "fetch failed (https://crumb-user:crumb-password@upstream.invalid/v1?token=crumb-token)");
            crate::error_response(axum::http::StatusCode::BAD_GATEWAY, "upstream failed", DeployError(UpstreamError))
        }));
        let response = crate::SentryLayer.layer(app).call(
            axum::http::Request::builder()
                .uri("/deploy?token=request-query-secret")
                .body(axum::body::Body::empty())
                .unwrap(),
        );
        use tracing::instrument::WithSubscriber;
        let subscriber = tracing_subscriber::registry().with(crate::RequestBreadcrumbLayer::new());
        let response = response.with_subscriber(subscriber).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
        crate::capture_error_with_breadcrumbs(&DeployError(UpstreamError), vec![sentry::Breadcrumb {
            category: Some("build::download".into()),
            message: Some("fetch failed https://job-user:job-password@upstream.invalid/v1?api_key=job-token".into()),
            ..Default::default()
        }]);

        let (events, wire) = captured(&transport);
        assert_eq!(
            events.len(),
            2,
            "request and background paths must both report"
        );
        for secret in [
            "url-user",
            "url-password",
            "query-secret",
            "fragment-secret",
            "crumb-user",
            "crumb-password",
            "crumb-token",
            "job-user",
            "job-password",
            "job-token",
            "request-query-secret",
        ] {
            assert!(!wire.contains(secret), "outgoing envelope leaked {secret}");
        }
        for event in &events {
            assert_eq!(event.exception.len(), 2);
            assert_eq!(event.exception[0].ty, "UpstreamError");
            assert_eq!(
                event.exception[0].value.as_deref(),
                Some("upstream 502 for https://upstream.invalid/v1 [src/upstream.rs:12:3]")
            );
            assert_eq!(event.exception[1].ty, "DeployError");
            assert_eq!(
                event.exception[1].value.as_deref(),
                Some("deployment failed [src/deploy.rs:20:5]")
            );
            assert_eq!(event.tags["error.location.0"], "src/deploy.rs:20:5");
            assert_eq!(event.tags["error.location.1"], "src/upstream.rs:12:3");
        }
        assert_eq!(events[0].tags["http.path"], "/deploy");
        assert_eq!(events[0].tags["http.status_code"], "502");
        assert_eq!(events[0].breadcrumbs.len(), 1);
        assert_eq!(
            events[0].breadcrumbs[0].category.as_deref(),
            Some("deploy::upstream")
        );
        assert_eq!(
            events[0].breadcrumbs[0].data["status"].as_str(),
            Some("502")
        );
        assert_eq!(
            events[0].breadcrumbs[0].message.as_deref(),
            Some("fetch failed (https://upstream.invalid/v1)")
        );
        assert_eq!(
            events[1].breadcrumbs[0].category.as_deref(),
            Some("build::download")
        );
    }
}

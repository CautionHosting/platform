// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::borrow::Cow;

use sentry::protocol::{Event, Value};
use sentry::types::Dsn;

const FILTERED: &str = "[Filtered]";
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "private_key",
    "apikey",
    "api_key",
    "database_url",
    "dsn",
    "smtp",
    "paddle",
    "webhook",
    "attestation",
    "nonce",
    "certificate",
    "pcr",
    "locksmith",
    "shard",
    "credential",
    "webauthn",
];

/// Initializes Sentry for an operator-facing platform service when `SENTRY_DSN` is set.
///
/// Returns `None` when Sentry is not configured or the DSN is invalid, leaving service
/// behavior unchanged. The returned guard must be kept alive for the service lifetime.
pub fn init_sentry(service_name: &'static str) -> Option<sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok()?.trim().to_owned();
    if dsn.is_empty() {
        return None;
    }

    let dsn = dsn.parse::<Dsn>().ok()?;
    let environment = optional_env("SENTRY_ENVIRONMENT");
    let release = optional_env("SENTRY_RELEASE");

    let options = sentry::ClientOptions::new()
        .send_default_pii(false)
        .traces_sample_rate(0.0)
        .sample_rate(1.0)
        .before_send(|event| Some(sanitize_event(event)));

    let options = sentry::ClientOptions {
        dsn: Some(dsn),
        environment,
        release,
        ..options
    };

    let guard = sentry::init(options);
    sentry::configure_scope(|scope| {
        scope.set_tag("service", service_name);
    });

    Some(guard)
}

fn optional_env(name: &str) -> Option<Cow<'static, str>> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(Cow::Owned)
}

fn sanitize_event(mut event: Event<'static>) -> Event<'static> {
    event.user = None;
    event.request = None;

    if let Some(message) = event.message.as_mut() {
        *message = redact_text(message);
    }

    if let Some(logentry) = event.logentry.as_mut() {
        logentry.message = redact_text(&logentry.message);
        for param in &mut logentry.params {
            sanitize_value(param);
        }
    }

    for exception in &mut event.exception.values {
        if let Some(value) = exception.value.as_mut() {
            *value = redact_text(value);
        }
        if let Some(mechanism) = exception.mechanism.as_mut() {
            if let Some(description) = mechanism.description.as_mut() {
                *description = redact_text(description);
            }
            sanitize_map(&mut mechanism.data);
        }
    }

    for breadcrumb in &mut event.breadcrumbs.values {
        if let Some(message) = breadcrumb.message.as_mut() {
            *message = redact_text(message);
        }
        sanitize_map(&mut breadcrumb.data);
    }

    sanitize_map(&mut event.extra);
    event
}

fn sanitize_map(map: &mut sentry::protocol::Map<String, Value>) {
    for (key, value) in map.iter_mut() {
        if is_sensitive_key(key) {
            *value = Value::String(FILTERED.to_string());
        } else {
            sanitize_value(value);
        }
    }
}

fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_text(text),
        Value::Array(values) => {
            for value in values {
                sanitize_value(value);
            }
        }
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *value = Value::String(FILTERED.to_string());
                } else {
                    sanitize_value(value);
                }
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn redact_text(text: &str) -> String {
    text.lines().map(redact_line).collect::<Vec<_>>().join("\n")
}

fn redact_line(line: &str) -> String {
    if !is_sensitive_key(line) {
        return line.to_string();
    }

    for separator in [": ", "=", ":"] {
        if let Some((key, _)) = line.split_once(separator) {
            return format!("{}{}{}", key, separator, FILTERED);
        }
    }

    FILTERED.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_sentry_env() {
        std::env::remove_var("SENTRY_DSN");
        std::env::remove_var("SENTRY_ENVIRONMENT");
        std::env::remove_var("SENTRY_RELEASE");
    }

    #[test]
    #[serial]
    fn sentry_is_disabled_without_dsn() {
        clear_sentry_env();

        let guard = init_sentry("api");

        assert!(guard.is_none());
    }

    #[test]
    fn sensitive_key_names_are_detected_case_insensitively() {
        assert!(is_sensitive_key("Authorization"));
        assert!(is_sensitive_key("paddle_webhook_secret"));
        assert!(is_sensitive_key("DATABASE_URL"));
        assert!(is_sensitive_key("webauthn_credential"));
        assert!(is_sensitive_key("attestation_document"));
        assert!(!is_sensitive_key("service"));
        assert!(!is_sensitive_key("environment"));
    }

    #[test]
    fn sensitive_values_are_redacted_from_text() {
        let text = "Authorization: Bearer abc123\nDATABASE_URL=postgres://user:shh@example/db";

        let redacted = redact_text(text);

        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("postgres://user:shh@example/db"));
        assert!(!redacted.contains("Bearer"));
        assert_eq!(redacted.matches(FILTERED).count(), 2);
    }

    #[test]
    fn sanitize_event_drops_request_and_user_and_redacts_extra() {
        let mut event = Event::default();
        event.request = Some(Default::default());
        event.user = Some(Default::default());
        event.extra.insert(
            "database_url".to_string(),
            Value::String("postgres://user:shh@example/db".to_string()),
        );
        event
            .extra
            .insert("safe".to_string(), Value::String("kept".to_string()));

        let event = sanitize_event(event);

        assert!(event.request.is_none());
        assert!(event.user.is_none());
        assert_eq!(
            event.extra.get("database_url"),
            Some(&Value::String(FILTERED.to_string()))
        );
        assert_eq!(
            event.extra.get("safe"),
            Some(&Value::String("kept".to_string()))
        );
    }
}

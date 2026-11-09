// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Route-based RBAC enforcement.
//!
//! Rules are `effect + method + route-template path (+ objects + priority)`.
//! Owners bypass everything; everyone else is denied unless a matching rule
//! admits the request. A request matches a rule when the method matches
//! (`*` = any), the route template equals the rule path, and every entry in
//! the rule's `objects` map admits the corresponding path parameter. Among
//! matching rules the lowest priority wins; equal-priority conflicts deny. No
//! match denies.

pub(crate) mod handlers;
pub(crate) mod inventory;

use std::sync::Arc;

use axum::{
    extract::{Extension, MatchedPath, RawPathParams, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde_json::Value;

use crate::{AppState, AuthContext};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Decision {
    Allow,
    Deny,
}

/// A single rule as stored for one of the caller's roles.
#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) effect: RuleEffect,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) objects: Option<Value>,
    pub(crate) priority: i32,
}

/// Evaluates the caller's effective rules for one request. Deny by default.
pub(crate) fn decide(
    method: &Method,
    matched_path: &str,
    params: &[(String, String)],
    rules: &[Rule],
) -> Decision {
    let method = method.as_str();
    let mut best: Option<i32> = None;
    let mut best_allow = false;

    for rule in rules {
        if !rule_matches(rule, method, matched_path, params) {
            continue;
        }
        match best {
            None => {
                best = Some(rule.priority);
                best_allow = rule.effect == RuleEffect::Allow;
            }
            Some(priority) if rule.priority < priority => {
                best = Some(rule.priority);
                best_allow = rule.effect == RuleEffect::Allow;
            }
            Some(priority) if rule.priority == priority => {
                // Equal-priority conflict fails closed.
                if rule.effect == RuleEffect::Deny {
                    best_allow = false;
                }
            }
            Some(_) => {}
        }
    }

    if best.is_some() && best_allow {
        Decision::Allow
    } else {
        Decision::Deny
    }
}

fn rule_matches(
    rule: &Rule,
    method: &str,
    matched_path: &str,
    params: &[(String, String)],
) -> bool {
    if rule.method != "*" && rule.method != method {
        return false;
    }
    if !path_matches(&rule.path, matched_path) {
        return false;
    }
    match &rule.objects {
        None => true,
        Some(Value::Object(map)) => map.iter().all(|(key, allowed)| {
            param_value(params, key).is_some_and(|value| allowed_value_matches(allowed, value))
        }),
        // A non-object `objects` cannot be satisfied; fail closed.
        Some(_) => false,
    }
}

/// Matches a rule path against a request's route template. `*` matches any
/// route; a path ending in `*` matches any route with that prefix (for example
/// `/resources/*`); anything else is an exact template match.
fn path_matches(rule_path: &str, matched_path: &str) -> bool {
    if rule_path == "*" {
        return true;
    }
    if let Some(prefix) = rule_path.strip_suffix('*') {
        return matched_path.starts_with(prefix);
    }
    rule_path == matched_path
}

fn param_value<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn allowed_value_matches(allowed: &Value, value: &str) -> bool {
    // Only arrays are valid: `["*"]` or a list of concrete values. Anything
    // else (a bare string, a number, an object) never matches.
    match allowed {
        Value::Array(entries) => entries.iter().any(|entry| match entry {
            Value::String(entry) => entry == "*" || entry == value,
            _ => false,
        }),
        _ => false,
    }
}

/// Failure modes for [`rbac_middleware`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RbacError {
    #[error("failed to load authorization rules [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("forbidden [{location}]")]
    Forbidden { location: Location },
}

impl IntoResponse for RbacError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            RbacError::Database { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            RbacError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
        };
        sentry_middleware::error_response(status, body, self)
    }
}

/// One row of the membership + rules join. `member_role` is always present; the
/// rule columns are NULL when the member has no roles (or a role has no rules).
#[derive(sqlx::FromRow)]
struct MembershipRuleRow {
    member_role: String,
    effect: Option<String>,
    method: Option<String>,
    path: Option<String>,
    objects: Option<Value>,
    priority: Option<i32>,
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = ?auth.user_id()))]
pub(crate) async fn rbac_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    params: RawPathParams,
    request: Request,
    next: Next,
) -> Result<Response, RbacError> {
    use RbacErrorCtx as Ctx;

    let method = request.method().clone();
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let params: Vec<(String, String)> = params
        .iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();

    // Users are evaluated against their membership roles; a token against the
    // (immutable) roles attached to it. Either way a token is never an owner
    // (D12), so the owner short-circuit below only ever fires for users.
    let rows: Vec<MembershipRuleRow> = match &auth {
        AuthContext::Token(token) => sqlx::query_as(
            "SELECT 'member'::text AS member_role,
                    r.effect, r.method, r.path, r.objects, r.priority
             FROM organization_access_token_roles tr
             LEFT JOIN rbac_role_rules r ON r.role_id = tr.role_id
             WHERE tr.token_id = $1",
        )
        .bind(token.token_id)
        .fetch_all(&state.db)
        .await
        .with_context(Ctx::database())?,
        AuthContext::User(_) => sqlx::query_as(
            "SELECT om.role::text AS member_role,
                    r.effect, r.method, r.path, r.objects, r.priority
             FROM organization_members om
             LEFT JOIN rbac_member_roles mr
                    ON mr.organization_id = om.organization_id AND mr.user_id = om.user_id
             LEFT JOIN rbac_role_rules r ON r.role_id = mr.role_id
             WHERE om.user_id = $1",
        )
        .bind(auth.user_id())
        .fetch_all(&state.db)
        .await
        .with_context(Ctx::database())?,
    };

    // Owners hold god powers and are not RBAC-gated.
    if rows.iter().any(|row| row.member_role == "owner") {
        return Ok(next.run(request).await);
    }

    let rules: Vec<Rule> = rows
        .into_iter()
        .filter_map(|row| {
            let (Some(effect), Some(method), Some(path), Some(priority)) =
                (row.effect, row.method, row.path, row.priority)
            else {
                return None;
            };
            Some(Rule {
                effect: if effect == "deny" {
                    RuleEffect::Deny
                } else {
                    RuleEffect::Allow
                },
                method,
                path,
                objects: row.objects,
                priority,
            })
        })
        .collect();

    // A request with no matched route template cannot be authorized.
    let Some(matched_path) = matched_path else {
        return Err(RbacError::Forbidden {
            location: std::panic::Location::caller(),
        });
    };

    match decide(&method, &matched_path, &params, &rules) {
        Decision::Allow => Ok(next.run(request).await),
        Decision::Deny => Err(RbacError::Forbidden {
            location: std::panic::Location::caller(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(effect: RuleEffect, method: &str, path: &str) -> Rule {
        Rule {
            effect,
            method: method.to_string(),
            path: path.to_string(),
            objects: None,
            priority: 0,
        }
    }

    fn params(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_rules_denies() {
        assert_eq!(decide(&Method::GET, "/users/me", &[], &[]), Decision::Deny);
    }

    #[test]
    fn exact_method_and_path_allows() {
        let rules = vec![rule(RuleEffect::Allow, "GET", "/users/me")];
        assert_eq!(
            decide(&Method::GET, "/users/me", &[], &rules),
            Decision::Allow
        );
        assert_eq!(
            decide(&Method::POST, "/users/me", &[], &rules),
            Decision::Deny
        );
        assert_eq!(
            decide(&Method::GET, "/resources", &[], &rules),
            Decision::Deny
        );
    }

    #[test]
    fn wildcard_method_matches_any() {
        let rules = vec![rule(RuleEffect::Allow, "*", "/resources/{id}")];
        assert_eq!(
            decide(
                &Method::DELETE,
                "/resources/{id}",
                &params(&[("id", "x")]),
                &rules
            ),
            Decision::Allow
        );
    }

    #[test]
    fn object_constraints_admit_only_listed_values() {
        let rules = vec![Rule {
            effect: RuleEffect::Allow,
            method: "POST".to_string(),
            path: "/resources/{id}/deployments".to_string(),
            objects: Some(json!({"id": ["11111111-1111-1111-1111-111111111111"]})),
            priority: 0,
        }];
        assert_eq!(
            decide(
                &Method::POST,
                "/resources/{id}/deployments",
                &params(&[("id", "11111111-1111-1111-1111-111111111111")]),
                &rules
            ),
            Decision::Allow
        );
        assert_eq!(
            decide(
                &Method::POST,
                "/resources/{id}/deployments",
                &params(&[("id", "22222222-2222-2222-2222-222222222222")]),
                &rules
            ),
            Decision::Deny
        );
    }

    #[test]
    fn object_wildcard_and_missing_param() {
        let rules = vec![Rule {
            effect: RuleEffect::Allow,
            method: "*".to_string(),
            path: "/resources/{id}".to_string(),
            objects: Some(json!({"id": ["*"]})),
            priority: 0,
        }];
        assert_eq!(
            decide(
                &Method::GET,
                "/resources/{id}",
                &params(&[("id", "anything")]),
                &rules
            ),
            Decision::Allow
        );
        // The required parameter is absent, so the rule cannot match.
        assert_eq!(
            decide(&Method::GET, "/resources/{id}", &[], &rules),
            Decision::Deny
        );
    }

    #[test]
    fn lowest_priority_wins() {
        let mut allow = rule(RuleEffect::Allow, "GET", "/billing/usage");
        allow.priority = 10;
        let mut deny = rule(RuleEffect::Deny, "GET", "/billing/usage");
        deny.priority = 5;
        // Lower (5) deny beats higher (10) allow.
        assert_eq!(
            decide(&Method::GET, "/billing/usage", &[], &[allow.clone(), deny]),
            Decision::Deny
        );
        // Lower allow beats higher deny.
        let mut allow_low = rule(RuleEffect::Allow, "GET", "/billing/usage");
        allow_low.priority = 1;
        let mut deny_high = rule(RuleEffect::Deny, "GET", "/billing/usage");
        deny_high.priority = 9;
        assert_eq!(
            decide(&Method::GET, "/billing/usage", &[], &[allow_low, deny_high]),
            Decision::Allow
        );
    }

    #[test]
    fn equal_priority_conflict_denies() {
        let allow = rule(RuleEffect::Allow, "GET", "/billing/usage");
        let deny = rule(RuleEffect::Deny, "GET", "/billing/usage");
        assert_eq!(
            decide(&Method::GET, "/billing/usage", &[], &[allow, deny]),
            Decision::Deny
        );
    }

    #[test]
    fn path_matching_supports_wildcards() {
        assert!(path_matches("*", "/resources/{id}"));
        assert!(path_matches("/resources/*", "/resources/{id}"));
        assert!(path_matches("/resources/*", "/resources/{id}/deployments"));
        assert!(!path_matches("/resources/*", "/resources"));
        assert!(!path_matches("/billing/*", "/resources/{id}"));
        assert!(path_matches("/users/me", "/users/me"));
        assert!(!path_matches("/users/me", "/users"));
        // A catch-all rule admits any route.
        let wildcard = rule(RuleEffect::Allow, "*", "*");
        assert_eq!(
            decide(&Method::DELETE, "/organizations/{id}", &[], &[wildcard]),
            Decision::Allow
        );
    }

    #[test]
    fn object_value_must_be_an_array() {
        // A bare string is not a valid `objects` value and fails closed.
        let rules = vec![Rule {
            effect: RuleEffect::Allow,
            method: "GET".to_string(),
            path: "/resources/{id}".to_string(),
            objects: Some(json!({"id": "*"})),
            priority: 0,
        }];
        assert_eq!(
            decide(
                &Method::GET,
                "/resources/{id}",
                &params(&[("id", "anything")]),
                &rules
            ),
            Decision::Deny
        );
    }
}

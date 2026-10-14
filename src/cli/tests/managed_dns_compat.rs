// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use cli::{App, CreateAppResponse};

#[test]
fn app_responses_from_older_servers_remain_compatible() {
    let app: App = serde_json::from_value(serde_json::json!({
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "resource_name": "example",
        "state": "running",
        "provider_resource_id": "i-123",
        "public_ip": "192.0.2.1",
        "domain": null,
        "configuration": {},
        "git_url": "git@example:app.git"
    }))
    .unwrap();

    assert!(app.managed_hostname.is_none());
    assert!(app.dns_status.is_none());
    assert!(app.dns_error.is_none());
}

#[test]
fn create_responses_from_older_servers_remain_compatible() {
    let app: CreateAppResponse = serde_json::from_value(serde_json::json!({
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "resource_name": "example",
        "git_url": "git@example:app.git",
        "state": "initialized"
    }))
    .unwrap();

    assert!(app.managed_hostname.is_none());
    assert!(app.dns_status.is_none());
    assert!(app.dns_error.is_none());
}

#[test]
fn app_responses_carry_m3_summary_fields() {
    let app: App = serde_json::from_value(serde_json::json!({
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "resource_name": "example",
        "state": "running",
        "provider_resource_id": "i-123",
        "public_ip": "192.0.2.1",
        "domain": null,
        "configuration": {},
        "git_url": "git@example:app.git",
        "lifecycle": "deployments",
        "summary_state": "running",
        "active": true,
        "live_commit_sha": "ff43fef0123",
        "candidates": 1,
        "candidate_limit": 3
    }))
    .unwrap();

    assert_eq!(app.summary_state.as_deref(), Some("running"));
    assert_eq!(app.active, Some(true));
    assert_eq!(app.live_commit_sha.as_deref(), Some("ff43fef0123"));
    assert_eq!(app.candidates, Some(1));
    assert_eq!(app.candidate_limit, Some(3));

    let m1: App = serde_json::from_value(serde_json::json!({
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "resource_name": "example",
        "state": "running",
        "provider_resource_id": "i-123",
        "public_ip": "192.0.2.1",
        "domain": null,
        "configuration": {},
        "git_url": "git@example:app.git",
        "lifecycle": "deployments",
        "live_deployment_id": "d1"
    }))
    .unwrap();

    assert!(m1.summary_state.is_none());
    assert!(m1.active.is_none());
    assert!(m1.live_commit_sha.is_none());
    assert!(m1.candidates.is_none());
    assert!(m1.candidate_limit.is_none());
}

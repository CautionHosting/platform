use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, ec2, deployment, cloud_credentials, metering};

/// Helper: call the internal unsuspend endpoint (used after credit purchase/auto-topup).
pub async fn call_internal_unsuspend(state: &AppState, org_id: Uuid) -> Result<(), String> {
    let secret = state.internal_service_secret.as_deref().unwrap_or_default();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:8080/internal/org/{}/unsuspend", org_id))
        .header("x-internal-service-secret", secret)
        .send()
        .await
        .map_err(|e| format!("Failed to call unsuspend: {}", e))?;

    if resp.status().is_success() {
        tracing::info!("Unsuspended org {} after credit deposit", org_id);
        Ok(())
    } else {
        Err(format!("Unsuspend returned {}", resp.status()))
    }
}

/// Internal endpoint: suspend only fully-managed resources for an org (credit exhaustion).
/// Unlike suspend_org_resources which suspends ALL resources, this only suspends resources
/// that are NOT managed on-prem — credit exhaustion should not affect BYOC deployments.
pub async fn suspend_managed_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Suspending fully-managed resources for org {} (credit exhaustion)", org_id);

    let resources: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT cr.id, cr.resource_name, cr.provider_resource_id FROM compute_resources cr
         WHERE cr.organization_id = $1 AND cr.state = 'running'
           AND NOT EXISTS (
               SELECT 1 FROM cloud_credentials cc
               WHERE cc.resource_id = cr.id AND cc.managed_on_prem = true
           )"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut stopped = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name, provider_resource_id) in &resources {
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["running"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.stop_instances(&ids).await {
                        tracing::error!("Failed to stop instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Stopped {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No running instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        if let Err(e) = sqlx::query("UPDATE compute_resources SET state = 'stopped' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await {
            tracing::error!("Failed to mark resource {} as stopped: {}", resource_id, e);
        }

        if let Err(e) = metering::stop_tracked_resource(
            state.internal_service_secret.as_deref(),
            provider_resource_id,
        )
        .await {
            tracing::error!("Failed to stop metering for resource {}: {}", resource_id, e);
            let _ = sqlx::query(
                "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
            )
            .bind(provider_resource_id)
            .execute(&state.db)
            .await;
        }
        stopped += 1;
    }

    Ok(Json(serde_json::json!({
        "stopped": stopped,
        "total": resources.len(),
        "errors": errors,
    })))
}

/// Internal endpoint: suspend all running resources for an org (stop EC2 instances).
/// Called by the metering service during dunning enforcement.
pub async fn suspend_org_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Suspending all running resources for org {}", org_id);

    let resources: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, resource_name, provider_resource_id FROM compute_resources
         WHERE organization_id = $1 AND state = 'running'"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut stopped = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name, provider_resource_id) in &resources {
        // Get AWS credentials for this resource
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["running"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.stop_instances(&ids).await {
                        tracing::error!("Failed to stop instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Stopped {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No running instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        // Mark resource as stopped in DB regardless
        if let Err(e) = sqlx::query("UPDATE compute_resources SET state = 'stopped' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await {
            tracing::error!("Failed to mark resource {} as stopped: {}", resource_id, e);
        }

        if let Err(e) = metering::stop_tracked_resource(
            state.internal_service_secret.as_deref(),
            provider_resource_id,
        )
        .await {
            tracing::error!("Failed to stop metering for resource {}: {}", resource_id, e);
            let _ = sqlx::query(
                "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
            )
            .bind(provider_resource_id)
            .execute(&state.db)
            .await;
        }
        stopped += 1;
    }

    // Mark org as suspended
    if let Err(e) = sqlx::query(
        "UPDATE organizations SET dunning_stage = 'suspended' WHERE id = $1"
    )
    .bind(org_id)
    .execute(&state.db)
    .await {
        tracing::error!("Failed to update dunning_stage for org {}: {}", org_id, e);
    }

    Ok(Json(serde_json::json!({
        "stopped": stopped,
        "total": resources.len(),
        "errors": errors,
    })))
}

/// Internal endpoint: unsuspend org — restart stopped resources and clear dunning state.
/// Called when payment is resolved (credit deposit, new payment method, etc).
pub async fn unsuspend_org_resources(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    tracing::info!("Unsuspending resources for org {}", org_id);

    let resources: Vec<(Uuid, String, String, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT id, resource_name, provider_resource_id, region, configuration FROM compute_resources
         WHERE organization_id = $1 AND state = 'stopped'"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    let mut started = 0u32;
    let mut errors = Vec::new();

    for (resource_id, resource_name, provider_resource_id, region, configuration) in &resources {
        let aws_creds = get_aws_credentials_for_resource(&state, org_id, *resource_id).await;

        if let Some(creds) = aws_creds {
            let ec2 = ec2::Ec2Client::new(&creds);
            let tag_filter = ec2::Filter::new("tag:Name", &[resource_name.as_str()]);
            let state_filter = ec2::Filter::new("instance-state-name", &["stopped"]);

            match ec2.describe_instances(&[tag_filter, state_filter]).await {
                Ok(instances) if !instances.is_empty() => {
                    let ids: Vec<String> = instances.iter().map(|i| i.instance_id.clone()).collect();
                    if let Err(e) = ec2.start_instances(&ids).await {
                        tracing::error!("Failed to start instances for {}: {}", resource_name, e);
                        errors.push(format!("{}: {}", resource_name, e));
                        continue;
                    }
                    tracing::info!("Started {} instance(s) for resource {}", ids.len(), resource_name);
                }
                Ok(_) => {
                    tracing::info!("No stopped instances found for resource {}", resource_name);
                }
                Err(e) => {
                    tracing::error!("Failed to describe instances for {}: {}", resource_name, e);
                    errors.push(format!("{}: {}", resource_name, e));
                    continue;
                }
            }
        }

        if let Err(e) = sqlx::query("UPDATE compute_resources SET state = 'running' WHERE id = $1")
            .bind(resource_id)
            .execute(&state.db)
            .await {
            tracing::error!("Failed to mark resource {} as running: {}", resource_id, e);
        }

        let instance_type = configuration
            .as_ref()
            .and_then(|config| config.get("instance_type"))
            .and_then(|value| value.as_str());
        let metadata = serde_json::json!({
            "resource_kind": "compute_resource",
            "compute_resource_id": resource_id.to_string(),
            "instance_id": provider_resource_id,
            "resource_name": resource_name,
        });
        if let Err(e) = metering::upsert_tracked_resource(
            &state,
            provider_resource_id,
            org_id,
            None,
            *resource_id,
            "aws",
            instance_type,
            region.as_deref(),
            &metadata,
        )
        .await {
            tracing::error!("Failed to resume metering for resource {}: {}", resource_id, e);
        }
        started += 1;
    }

    // Clear dunning state
    if let Err(e) = sqlx::query(
        "UPDATE organizations SET payment_failed_at = NULL, dunning_stage = 'none' WHERE id = $1"
    )
    .bind(org_id)
    .execute(&state.db)
    .await {
        tracing::error!("Failed to clear dunning state for org {}: {}", org_id, e);
    }

    Ok(Json(serde_json::json!({
        "started": started,
        "total": resources.len(),
        "errors": errors,
    })))
}

/// Helper: get AWS credentials for a resource (managed on-prem or platform default).
pub async fn get_aws_credentials_for_resource(
    state: &AppState,
    org_id: Uuid,
    resource_id: Uuid,
) -> Option<deployment::AwsCredentials> {
    // Check for managed on-prem credentials first
    if let Some(encryptor) = state.encryptor.as_ref() {
        if let Ok(Some(credential)) = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id).await {
            if credential.managed_on_prem {
                if let Ok(Some(secrets)) = cloud_credentials::get_credential_secrets(&state.db, encryptor, org_id, credential.id).await {
                    let region = credential.config["aws_region"].as_str()
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("AWS_REGION").ok())
                        .unwrap_or_else(|| "us-west-2".to_string());
                    return Some(deployment::AwsCredentials {
                        access_key_id: secrets["aws_access_key_id"].as_str().unwrap_or("").to_string(),
                        secret_access_key: secrets["aws_secret_access_key"].as_str().unwrap_or("").to_string(),
                        region,
                    });
                }
            }
        }
    }

    // Fall back to platform credentials from env
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    Some(deployment::AwsCredentials {
        access_key_id,
        secret_access_key,
        region,
    })
}

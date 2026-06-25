use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct DestroyNextQuery {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum DestroyNextResponse {
    #[serde(rename = "deleted")]
    Deleted { resource_id: Uuid },
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "error")]
    Error { error: String },
}

impl IntoResponse for DestroyNextResponse {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DestroyNextResponse::Deleted { .. } => (StatusCode::OK, Json(&self)),
            DestroyNextResponse::Done => (StatusCode::OK, Json(&self)),
            DestroyNextResponse::Error { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(&self))
            }
        };
        (status, body).into_response()
    }
}

#[cfg(feature = "e2e-testing-unsafe")]
pub async fn destroy_next_app(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DestroyNextQuery>,
) -> Response {
    tracing::info!("destroy_next_app called (force={})", query.force);

    let resource = match sqlx::query_as::<_, (Uuid, Uuid, String, String, Option<String>)>(
        "SELECT cr.id, cr.organization_id, cr.resource_name, cr.provider_resource_id, cr.region
         FROM compute_resources cr
         WHERE cr.destroyed_at IS NULL
         ORDER BY cr.created_at ASC
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!("Database query failed in destroy_next_app: {:?}", e);
            return DestroyNextResponse::Error {
                error: "Database query failed".to_string(),
            }
            .into_response();
        }
    };

    let Some((resource_id, org_id, resource_name, provider_resource_id, resource_region)) =
        resource
    else {
        tracing::info!("destroy_next_app: no resources to destroy");
        return DestroyNextResponse::Done.into_response();
    };

    tracing::info!(
        "Destroying resource {} ({}) for org {}",
        resource_name,
        resource_id,
        org_id
    );

    let resource_region = resource_region
        .or_else(|| std::env::var("AWS_REGION").ok())
        .unwrap_or_else(|| "us-west-2".to_string());

    let (aws_credentials, asg_name) = if let Some(encryptor) = state.encryptor.as_ref() {
        if let Ok(Some(credential)) =
            crate::cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id)
                .await
        {
            if credential.managed_on_prem {
                if let Ok(Some(secrets)) = crate::cloud_credentials::get_credential_secrets(
                    &state.db,
                    encryptor,
                    org_id,
                    credential.id,
                )
                .await
                {
                    let region = credential.config["aws_region"]
                        .as_str()
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("AWS_REGION").ok())
                        .unwrap_or_else(|| "us-west-2".to_string());
                    let asg = credential.config["asg_name"]
                        .as_str()
                        .map(|s| s.to_string());
                    (
                        Some(crate::deployment::AwsCredentials {
                            access_key_id: secrets["aws_access_key_id"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            secret_access_key: secrets["aws_secret_access_key"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            region,
                        }),
                        asg,
                    )
                } else {
                    (None, None)
                }
            } else {
                (
                    Some(crate::fully_managed_capacity::platform_credentials_for_region(
                        &resource_region,
                    )),
                    None,
                )
            }
        } else {
            (
                Some(crate::fully_managed_capacity::platform_credentials_for_region(
                    &resource_region,
                )),
                None,
            )
        }
    } else {
        (
            Some(crate::fully_managed_capacity::platform_credentials_for_region(
                &resource_region,
            )),
            None,
        )
    };

    let terraform_result = crate::deployment::destroy_app_with_credentials(
        org_id,
        resource_id,
        resource_name.clone(),
        aws_credentials,
        asg_name,
    )
    .await;

    if let Err(ref e) = terraform_result {
        tracing::error!(
            "Terraform destroy failed for resource {}: {}",
            resource_id,
            e
        );
        if !query.force {
            return DestroyNextResponse::Error {
                error: format!("Terraform destroy failed: {}", e),
            }
            .into_response();
        }
        tracing::warn!("Force flag set - marking resource as destroyed despite Terraform failure. AWS resources may still exist!");
    }

    let update_result = sqlx::query(
        "UPDATE compute_resources
         SET destroyed_at = NOW(), state = $1, public_ip = NULL, region = NULL
         WHERE id = $2 AND organization_id = $3",
    )
    .bind(crate::types::ResourceState::Terminated)
    .bind(resource_id)
    .bind(org_id)
    .execute(&state.db)
    .await;

    if let Err(e) = update_result {
        tracing::error!("Failed to mark resource as terminated: {:?}", e);
        return DestroyNextResponse::Error {
            error: "Failed to update resource record".to_string(),
        }
        .into_response();
    }

    match crate::metering::stop_tracked_resource(
        state.internal_service_secret.as_deref(),
        &provider_resource_id,
    )
    .await
    {
        Ok(()) => {
            tracing::info!("Stopped metering for resource {}", resource_id);
        }
        Err(e) => {
            tracing::error!(
                "Failed to stop metering for resource {} via metering service: {}",
                resource_id,
                e
            );
            let _ = sqlx::query(
                "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
            )
            .bind(&provider_resource_id)
            .execute(&state.db)
            .await;
        }
    }

    tracing::info!("Resource {} terminated", resource_id);

    DestroyNextResponse::Deleted { resource_id }.into_response()
}

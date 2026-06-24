// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::bail;
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, deployment, ec2, validation};

const CAPACITY_LOCK_ID: i64 = 7_650_001;
const STANDARD_ON_DEMAND_VCPU_QUOTA_CODE: &str = "L-1216C47A";
const ELASTIC_IP_QUOTA_CODE: &str = "L-0263D0A3";
const VPC_QUOTA_CODE: &str = "L-F678F1CE";
pub(crate) const MAX_FULLY_MANAGED_ENCLAVE_VCPUS: u32 = 16;
const CAPACITY_WAITLIST_PROMPT: &str = "No fully managed capacity is available right now. Please wait while Caution provisions additional resources. To be notified when capacity is available, run: caution capacity waitlist --email <email>";
const CAPACITY_ALREADY_WAITLISTED_MESSAGE: &str = "No fully managed capacity is available right now. Please wait while Caution provisions additional resources. You are already on the capacity waitlist.";

#[derive(Debug, Clone)]
pub(crate) struct DeploymentRequirements {
    pub(crate) instance_type: String,
    pub(crate) host_vcpus: u32,
    pub(crate) vpcs: u32,
    pub(crate) eips: u32,
}

impl DeploymentRequirements {
    pub(crate) fn for_enclave(cpus: u32, memory_mb: u32) -> Self {
        let (instance_type, host_vcpus) =
            deployment::host_instance_type_for_enclave(cpus, memory_mb);
        Self {
            instance_type: instance_type.to_string(),
            host_vcpus,
            vpcs: 1,
            eips: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CapacityReservation {
    pub(crate) id: Option<Uuid>,
    pub(crate) region: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CapacityError {
    #[error("No fully managed deployment regions are available.")]
    NoRegionsAvailable,
    #[error("{0}")]
    NoCapacity(String),
    #[error("Unable to check fully managed capacity right now. Please try again later.")]
    CheckFailed,
    #[error("Database error while reserving fully managed capacity.")]
    Database(#[from] sqlx::Error),
}

impl CapacityError {
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            CapacityError::NoRegionsAvailable => StatusCode::SERVICE_UNAVAILABLE,
            CapacityError::NoCapacity(_) => StatusCode::SERVICE_UNAVAILABLE,
            CapacityError::CheckFailed => StatusCode::SERVICE_UNAVAILABLE,
            CapacityError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug)]
struct RegionCapacity {
    vpc_quota: u32,
    vpcs_used: u32,
    eip_quota: u32,
    eips_used: u32,
    host_vcpu_quota: u32,
    host_vcpus_used: u32,
    pending_vpcs: u32,
    pending_eips: u32,
    pending_host_vcpus: u32,
}

impl RegionCapacity {
    fn has_room_for(&self, requirements: &DeploymentRequirements) -> bool {
        self.available_vpcs() >= requirements.vpcs
            && self.available_eips() >= requirements.eips
            && self.available_host_vcpus() >= requirements.host_vcpus
    }

    fn available_vpcs(&self) -> u32 {
        self.vpc_quota.saturating_sub(
            self.vpcs_used
                .saturating_add(self.pending_vpcs)
                .saturating_add(reserve_vpcs()),
        )
    }

    fn available_eips(&self) -> u32 {
        self.eip_quota.saturating_sub(
            self.eips_used
                .saturating_add(self.pending_eips)
                .saturating_add(reserve_eips()),
        )
    }

    fn available_host_vcpus(&self) -> u32 {
        self.host_vcpu_quota.saturating_sub(
            self.host_vcpus_used
                .saturating_add(self.pending_host_vcpus)
                .saturating_add(reserve_host_vcpus()),
        )
    }
}

async fn candidate_regions() -> anyhow::Result<Vec<String>> {
    let discovery_credentials = platform_credentials_for_region("us-east-1");
    let ec2 = ec2::Ec2Client::new(&discovery_credentials);
    let mut regions: Vec<String> = ec2
        .describe_regions(true)
        .await?
        .into_iter()
        .filter(|region| {
            matches!(
                region.opt_in_status.as_deref(),
                None | Some("opt-in-not-required") | Some("opted-in")
            )
        })
        .map(|region| region.name)
        .collect();
    regions.sort();
    Ok(regions)
}

pub(crate) async fn reserve_capacity(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    resource_id: Uuid,
    requirements: &DeploymentRequirements,
) -> Result<CapacityReservation, CapacityError> {
    let candidates = candidate_regions().await.map_err(|error| {
        tracing::warn!(
            "Failed to discover fully managed deployment regions: {:#}",
            error
        );
        CapacityError::CheckFailed
    })?;

    if candidates.is_empty() {
        return Err(CapacityError::NoRegionsAvailable);
    }

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CAPACITY_LOCK_ID)
        .execute(&mut *tx)
        .await?;

    let mut checked_any_region = false;
    let mut last_error = None;
    for region in candidates {
        let credentials = platform_credentials_for_region(&region);
        let ec2 = ec2::Ec2Client::new(&credentials);
        match ec2.instance_type_offered(&requirements.instance_type).await {
            Ok(true) => {}
            Ok(false) => {
                checked_any_region = true;
                tracing::info!(
                    "Fully managed region {} does not offer required instance type {}",
                    region,
                    requirements.instance_type
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to check instance type offering in {}: {:#}",
                    region,
                    error
                );
                last_error = Some(error);
                continue;
            }
        }

        match region_capacity(&mut tx, &region).await {
            Ok(capacity) => {
                checked_any_region = true;
                if capacity.has_room_for(requirements) {
                    let reservation_id: Uuid = sqlx::query_scalar(
                        "INSERT INTO fully_managed_capacity_reservations
                         (organization_id, resource_id, region, host_vcpus, vpcs, eips)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         RETURNING id",
                    )
                    .bind(org_id)
                    .bind(resource_id)
                    .bind(&region)
                    .bind(requirements.host_vcpus as i32)
                    .bind(requirements.vpcs as i32)
                    .bind(requirements.eips as i32)
                    .fetch_one(&mut *tx)
                    .await?;

                    tx.commit().await?;
                    tracing::info!(
                        "Reserved fully managed capacity: resource_id={}, region={}, instance_type={}, host_vcpus={}, vpcs={}, eips={}",
                        resource_id,
                        region,
                        requirements.instance_type,
                        requirements.host_vcpus,
                        requirements.vpcs,
                        requirements.eips
                    );
                    return Ok(CapacityReservation {
                        id: Some(reservation_id),
                        region,
                    });
                }

                tracing::info!(
                    "Fully managed region {} lacks capacity: available vpcs={}, eips={}, host_vcpus={}; required vpcs={}, eips={}, host_vcpus={}",
                    region,
                    capacity.available_vpcs(),
                    capacity.available_eips(),
                    capacity.available_host_vcpus(),
                    requirements.vpcs,
                    requirements.eips,
                    requirements.host_vcpus
                );
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to check fully managed capacity in {}: {:#}",
                    region,
                    error
                );
                last_error = Some(error);
            }
        }
    }

    if checked_any_region {
        let already_waitlisted = user_has_waitlist_entry(&mut tx, org_id, user_id).await?;
        tx.rollback().await?;
        let message = if already_waitlisted {
            CAPACITY_ALREADY_WAITLISTED_MESSAGE
        } else {
            CAPACITY_WAITLIST_PROMPT
        };
        Err(CapacityError::NoCapacity(message.to_string()))
    } else {
        let _ = last_error;
        tx.rollback().await?;
        Err(CapacityError::CheckFailed)
    }
}

pub(crate) async fn release_reservation(pool: &PgPool, reservation: &CapacityReservation) {
    let Some(reservation_id) = reservation.id else {
        return;
    };

    if let Err(error) = sqlx::query(
        "UPDATE fully_managed_capacity_reservations
         SET status = 'released'
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(reservation_id)
    .execute(pool)
    .await
    {
        tracing::warn!(
            "Failed to release fully managed capacity reservation {}: {}",
            reservation_id,
            error
        );
    }
}

async fn region_capacity(
    tx: &mut Transaction<'_, Postgres>,
    region: &str,
) -> anyhow::Result<RegionCapacity> {
    let credentials = platform_credentials_for_region(region);
    let ec2 = ec2::Ec2Client::new(&credentials);
    let quotas = ec2::ServiceQuotasClient::new(&credentials);

    let (pending_vpcs, pending_eips, pending_host_vcpus): (i64, i64, i64) = sqlx::query_as(
        "SELECT
             COALESCE(SUM(vpcs), 0),
             COALESCE(SUM(eips), 0),
             COALESCE(SUM(host_vcpus), 0)
         FROM fully_managed_capacity_reservations
         WHERE region = $1 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(region)
    .fetch_one(&mut **tx)
    .await?;

    let vpc_quota = quotas
        .get_service_quota_value("vpc", VPC_QUOTA_CODE)
        .await?
        .floor() as u32;
    let eip_quota = quotas
        .get_service_quota_value("ec2", ELASTIC_IP_QUOTA_CODE)
        .await?
        .floor() as u32;
    let host_vcpu_quota = quotas
        .get_service_quota_value("ec2", STANDARD_ON_DEMAND_VCPU_QUOTA_CODE)
        .await?
        .floor() as u32;

    let vpcs_used = ec2.count_vpcs().await?;
    let eips_used = ec2.count_elastic_ips().await?;
    let mut host_vcpus_used = 0;
    for instance_type in ec2.active_instance_types().await? {
        let Some(vcpus) = deployment::host_vcpus_for_instance_type(&instance_type) else {
            bail!(
                "Unknown active instance type reported by EC2: {}",
                instance_type
            );
        };
        host_vcpus_used += vcpus;
    }

    Ok(RegionCapacity {
        vpc_quota,
        vpcs_used,
        eip_quota,
        eips_used,
        host_vcpu_quota,
        host_vcpus_used,
        pending_vpcs: pending_vpcs.max(0) as u32,
        pending_eips: pending_eips.max(0) as u32,
        pending_host_vcpus: pending_host_vcpus.max(0) as u32,
    })
}

async fn user_has_waitlist_entry(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM fully_managed_capacity_waitlist
             WHERE organization_id = $1 AND user_id = $2 AND status = 'waiting'
         )",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
}

pub(crate) fn platform_credentials_for_region(region: &str) -> deployment::AwsCredentials {
    deployment::AwsCredentials {
        access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
        secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
        region: region.to_string(),
    }
}

fn reserve_vpcs() -> u32 {
    env_u32("FULLY_MANAGED_RESERVE_VPCS", 0)
}

fn reserve_eips() -> u32 {
    env_u32("FULLY_MANAGED_RESERVE_EIPS", 0)
}

fn reserve_host_vcpus() -> u32 {
    env_u32("FULLY_MANAGED_RESERVE_HOST_VCPUS", 0)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

#[derive(Debug, Deserialize)]
pub(crate) struct WaitlistRequest {
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) requested_enclave_vcpus: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WaitlistResponse {
    pub(crate) status: String,
}

pub(crate) async fn join_waitlist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<WaitlistRequest>,
) -> Result<Json<WaitlistResponse>, (StatusCode, String)> {
    crate::check_org_access(&state.db, auth.user_id, org_id)
        .await
        .map_err(|status| (status, "Organization access denied".to_string()))?;

    let email = payload.email.trim().to_lowercase();
    validation::validate_email(&email)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("Invalid email: {}", error)))?;

    if let Some(cpus) = payload.requested_enclave_vcpus {
        if cpus == 0 || cpus > MAX_FULLY_MANAGED_ENCLAVE_VCPUS {
            return Err((
                StatusCode::BAD_REQUEST,
                "requested_enclave_vcpus must be between 1 and 16; contact support for larger requests"
                    .to_string(),
            ));
        }
    }

    let required_host_vcpus = payload
        .requested_enclave_vcpus
        .map(|cpus| DeploymentRequirements::for_enclave(cpus, 512).host_vcpus as i32);

    let inserted: Option<bool> = sqlx::query_scalar(
        "INSERT INTO fully_managed_capacity_waitlist
         (organization_id, user_id, email, requested_enclave_vcpus, required_host_vcpus)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (organization_id, email) WHERE status = 'waiting'
         DO NOTHING
         RETURNING TRUE",
    )
    .bind(org_id)
    .bind(auth.user_id)
    .bind(&email)
    .bind(payload.requested_enclave_vcpus.map(|v| v as i32))
    .bind(required_host_vcpus)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        tracing::error!("Failed to insert fully managed waitlist entry: {}", error);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to join capacity waitlist".to_string(),
        )
    })?;

    let joined = inserted.unwrap_or(false);
    if joined {
        send_capacity_waitlist_alert(
            org_id,
            auth.user_id,
            email.clone(),
            payload.requested_enclave_vcpus,
            required_host_vcpus,
        );
    }

    Ok(Json(WaitlistResponse {
        status: if joined {
            "joined".to_string()
        } else {
            "already_waiting".to_string()
        },
    }))
}

fn send_capacity_waitlist_alert(
    org_id: Uuid,
    user_id: Uuid,
    email: String,
    requested_enclave_vcpus: Option<u32>,
    required_host_vcpus: Option<i32>,
) {
    let Some(to) = capacity_alert_recipient() else {
        return;
    };
    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    tokio::spawn(async move {
        match send_capacity_waitlist_alert_request(CapacityWaitlistAlert {
            email_service_url,
            to,
            org_id,
            user_id,
            email,
            requested_enclave_vcpus,
            required_host_vcpus,
        })
        .await
        {
            Ok(()) => {
                tracing::info!("Sent fully managed capacity waitlist alert");
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to send fully managed capacity waitlist alert: {}",
                    error
                );
            }
        }
    });
}

fn capacity_alert_recipient() -> Option<String> {
    std::env::var("CAPACITY_ALERT_TO")
        .ok()
        .map(|recipient| recipient.trim().to_string())
        .filter(|recipient| !recipient.is_empty())
}

#[derive(Debug)]
struct CapacityWaitlistAlert {
    email_service_url: String,
    to: String,
    org_id: Uuid,
    user_id: Uuid,
    email: String,
    requested_enclave_vcpus: Option<u32>,
    required_host_vcpus: Option<i32>,
}

async fn send_capacity_waitlist_alert_request(alert: CapacityWaitlistAlert) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|error| format!("failed to build email client: {}", error))?;

    let request = serde_json::json!({
        "to": alert.to,
        "template": "fully_managed_capacity_alert",
        "data": {
            "organization_id": alert.org_id,
            "user_id": alert.user_id,
            "email": alert.email,
            "requested_enclave_vcpus": alert.requested_enclave_vcpus,
            "required_host_vcpus": alert.required_host_vcpus,
        }
    });

    let response = client
        .post(format!("{}/send", alert.email_service_url))
        .json(&request)
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("email service returned {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, routing::post};
    use serde_json::Value;
    use tokio::sync::mpsc;

    async fn capture_email_request(
        State(tx): State<mpsc::Sender<Value>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        tx.send(payload).await.expect("capture email request");
        StatusCode::OK
    }

    #[tokio::test]
    async fn sends_capacity_waitlist_alert_email_request() {
        let (tx, mut rx) = mpsc::channel(1);
        let app = Router::new()
            .route("/send", post(capture_email_request))
            .with_state(tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub email service");
        let addr = listener.local_addr().expect("stub email service address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve stub email service");
        });

        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        send_capacity_waitlist_alert_request(CapacityWaitlistAlert {
            email_service_url: format!("http://{}", addr),
            to: "team@caution.test".to_string(),
            org_id,
            user_id,
            email: "user@example.test".to_string(),
            requested_enclave_vcpus: Some(4),
            required_host_vcpus: Some(8),
        })
        .await
        .expect("send capacity alert");

        let payload = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("receive email-service request")
            .expect("captured email-service request");

        assert_eq!(payload["to"], "team@caution.test");
        assert_eq!(payload["template"], "fully_managed_capacity_alert");
        assert_eq!(payload["data"]["organization_id"], org_id.to_string());
        assert_eq!(payload["data"]["user_id"], user_id.to_string());
        assert_eq!(payload["data"]["email"], "user@example.test");
        assert_eq!(payload["data"]["requested_enclave_vcpus"], 4);
        assert_eq!(payload["data"]["required_host_vcpus"], 8);

        server.abort();
    }
}

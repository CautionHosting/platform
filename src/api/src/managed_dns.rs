// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use async_trait::async_trait;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::{PgPool, Postgres, Transaction};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) const DEFAULT_MANAGED_DNS_SUFFIX: &str = "apps.caution.sh";
pub(crate) const MANAGED_DNS_TTL_SECS: i64 = 60;
const CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const CHANGE_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ARecordSet {
    ttl: i64,
    values: Vec<String>,
}

/// Failure modes for the Route53 helpers backing [`Route53Api`].
///
/// Messages are fixed literals without the internal location segment: these
/// errors are sanitized into the client-visible `dns_error` field.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum Route53ApiError {
    #[error("could not build managed DNS record")]
    BuildRecord {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not build managed DNS record set")]
    BuildSet {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not build Route53 change")]
    ChangeBuild {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not build Route53 change batch")]
    BatchBuild {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Route53 record change failed")]
    ChangeSend {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Route53 record change returned no change information")]
    NoChangeInfo {
        #[location]
        location: Location,
    },

    #[error("Route53 record lookup failed")]
    ListSend {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("managed Route53 A record has no TTL")]
    NoTtl {
        #[location]
        location: Location,
    },

    #[error("Route53 change status lookup failed")]
    StatusSend {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Route53 change lookup returned no change information")]
    NoStatusInfo {
        #[location]
        location: Location,
    },
}

#[async_trait]
trait Route53Api: Send + Sync {
    async fn upsert_a(
        &self,
        zone_id: &str,
        name: &str,
        ip: &str,
        ttl: i64,
    ) -> Result<String, Route53ApiError>;
    async fn delete_a(
        &self,
        zone_id: &str,
        name: &str,
        record: &ARecordSet,
    ) -> Result<String, Route53ApiError>;
    async fn get_a(&self, zone_id: &str, name: &str)
    -> Result<Option<ARecordSet>, Route53ApiError>;
    async fn change_is_insync(&self, change_id: &str) -> Result<bool, Route53ApiError>;
}

#[derive(Clone)]
struct AwsRoute53Api {
    client: aws_sdk_route53::Client,
}

impl AwsRoute53Api {
    async fn from_environment() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: aws_sdk_route53::Client::new(&config),
        }
    }

    #[tracing::instrument(skip_all, err)]
    fn rrset(
        name: &str,
        ttl: i64,
        values: &[String],
    ) -> Result<ResourceRecordSet, Route53ApiError> {
        use Route53ApiErrorCtx as Ctx;

        let records = values
            .iter()
            .map(|value| ResourceRecord::builder().value(value).build())
            .collect::<Result<Vec<_>, _>>()
            .with_context(Ctx::build_record())?;

        ResourceRecordSet::builder()
            .name(name)
            .r#type(RrType::A)
            .ttl(ttl)
            .set_resource_records(Some(records))
            .build()
            .with_context(Ctx::build_set())
    }

    #[tracing::instrument(skip_all, err)]
    async fn change(
        &self,
        zone_id: &str,
        action: ChangeAction,
        rrset: ResourceRecordSet,
    ) -> Result<String, Route53ApiError> {
        use Route53ApiErrorCtx as Ctx;

        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()
            .with_context(Ctx::change_build())?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .with_context(Ctx::batch_build())?;
        let output = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .with_context(Ctx::change_send())?;

        Ok(output
            .change_info()
            .ok_or_else(|| Route53ApiError::NoChangeInfo {
                location: std::panic::Location::caller(),
            })?
            .id()
            .to_string())
    }
}

#[async_trait]
impl Route53Api for AwsRoute53Api {
    #[tracing::instrument(skip_all, err)]
    async fn upsert_a(
        &self,
        zone_id: &str,
        name: &str,
        ip: &str,
        ttl: i64,
    ) -> Result<String, Route53ApiError> {
        let rrset = Self::rrset(name, ttl, &[ip.to_string()])?;
        self.change(zone_id, ChangeAction::Upsert, rrset).await
    }

    #[tracing::instrument(skip_all, err)]
    async fn delete_a(
        &self,
        zone_id: &str,
        name: &str,
        record: &ARecordSet,
    ) -> Result<String, Route53ApiError> {
        let rrset = Self::rrset(name, record.ttl, &record.values)?;
        self.change(zone_id, ChangeAction::Delete, rrset).await
    }

    #[tracing::instrument(skip_all, err)]
    async fn get_a(
        &self,
        zone_id: &str,
        name: &str,
    ) -> Result<Option<ARecordSet>, Route53ApiError> {
        use Route53ApiErrorCtx as Ctx;

        let output = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(zone_id)
            .start_record_name(name)
            .start_record_type(RrType::A)
            .max_items(1)
            .send()
            .await
            .with_context(Ctx::list_send())?;

        let Some(record) = output.resource_record_sets().first() else {
            return Ok(None);
        };
        if record.name().trim_end_matches('.') != name.trim_end_matches('.')
            || record.r#type() != &RrType::A
        {
            return Ok(None);
        }

        let ttl = record.ttl().ok_or_else(|| Route53ApiError::NoTtl {
            location: std::panic::Location::caller(),
        })?;
        let values = record
            .resource_records()
            .iter()
            .map(|record| record.value().to_string())
            .collect();
        Ok(Some(ARecordSet { ttl, values }))
    }

    #[tracing::instrument(skip_all, err)]
    async fn change_is_insync(&self, change_id: &str) -> Result<bool, Route53ApiError> {
        use Route53ApiErrorCtx as Ctx;

        let output = self
            .client
            .get_change()
            .id(change_id)
            .send()
            .await
            .with_context(Ctx::status_send())?;
        Ok(output
            .change_info()
            .ok_or_else(|| Route53ApiError::NoStatusInfo {
                location: std::panic::Location::caller(),
            })?
            .status()
            == &ChangeStatus::Insync)
    }
}

#[derive(Clone)]
pub(crate) struct ManagedDns {
    zone_id: String,
    suffix: String,
    api: Arc<dyn Route53Api>,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsSnapshot {
    pub(crate) status: String,
    pub(crate) error: Option<String>,
}

#[derive(Debug)]
struct DnsResource {
    public_ip: Option<String>,
    dns_status: String,
    dns_change_id: Option<String>,
    dns_release_not_before: Option<DateTime<Utc>>,
}

enum PublishProgress {
    Pending,
    Ready,
}

enum WithdrawalProgress {
    Pending,
    Wait(Duration),
    Safe,
}

/// Failure modes for [`ManagedDns::from_env`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum FromEnvError {
    #[error("could not read managed DNS suffix")]
    Suffix {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("CAUTION_APPS_DNS_ZONE_ID must be set in production")]
    ZoneIdRequired {
        #[location]
        location: Location,
    },
}

/// Failure modes for [`normalize_dns_suffix`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum NormalizeDnsSuffixError {
    #[error("CAUTION_APPS_DNS_SUFFIX must be a valid DNS suffix")]
    Invalid { location: Location },
}

/// Failure modes for the managed DNS publication pipeline
/// ([`ManagedDns::publish_once`] and [`ManagedDns::publish_resource`]).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PublishError {
    #[error("could not begin database transaction")]
    Transaction {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load managed DNS resource")]
    Load {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not commit database transaction")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource is not awaiting DNS publication")]
    NotPublishing {
        resource_id: Uuid,
        location: Location,
    },

    #[error("could not check Route53 change status")]
    Insync {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not update managed DNS record")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("cannot publish managed DNS without a public IP")]
    NoPublicIp {
        resource_id: Uuid,
        location: Location,
    },

    #[error("could not upsert managed DNS record")]
    Upsert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Route53 UPSERT did not reach INSYNC within 120 seconds")]
    PublishTimeout {
        resource_id: Uuid,
        location: Location,
    },
}

/// Failure modes for the managed DNS withdrawal pipeline
/// ([`ManagedDns::withdraw_once`] and [`ManagedDns::ensure_safe_to_release`]).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum WithdrawError {
    #[error("could not begin database transaction")]
    Transaction {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load managed DNS resource")]
    Load {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not commit database transaction")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource is not awaiting DNS withdrawal")]
    NotWithdrawing {
        resource_id: Uuid,
        location: Location,
    },

    #[error("could not check Route53 change status")]
    Insync {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not update managed DNS record")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("cannot prove DNS withdrawal without the retained public IP")]
    NoPublicIp {
        resource_id: Uuid,
        location: Location,
    },

    #[error("could not look up managed A record")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not upsert managed DNS record")]
    Upsert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("managed A record is still absent after conservative UPSERT")]
    StillAbsent {
        resource_id: Uuid,
        location: Location,
    },

    #[error("could not delete managed DNS record")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not wait for Route53 change to reach INSYNC")]
    Wait {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not fetch managed DNS resource")]
    Fetch {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not publish managed DNS before withdrawal")]
    Publish {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not transition managed DNS to withdrawal")]
    Transition {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid managed DNS status {status}")]
    InvalidStatus { status: String, location: Location },

    #[error("Route53 DELETE did not reach INSYNC within 120 seconds")]
    WithdrawTimeout {
        resource_id: Uuid,
        location: Location,
    },
}

/// Failure modes for [`ManagedDns::wait_for_change`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum WaitForChangeError {
    #[error("could not check Route53 change status")]
    Insync {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Route53 change did not reach INSYNC within 120 seconds")]
    Timeout {
        #[location]
        location: Location,
    },
}

/// Failure modes for [`dns_snapshot`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DnsSnapshotError {
    #[error("could not read managed DNS snapshot")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`begin_termination`]. The `Deploying` and `Gone` messages
/// are matched by exact string comparison in [`crate::resources`], so they carry
/// no location segment.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BeginTerminationError {
    #[error("could not update resource termination state")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource is deploying")]
    Deploying {
        #[location]
        location: Location,
    },

    #[error("resource no longer exists")]
    Gone {
        #[location]
        location: Location,
    },
}

/// Failure modes for [`begin_owned_deploy_rollback`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BeginOwnedDeployRollbackError {
    #[error("could not begin owned deploy rollback")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`transition_to_withdrawing`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TransitionToWithdrawingError {
    #[error("could not begin database transaction")]
    Transaction {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not update managed DNS withdrawal state")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource DNS is not ready for withdrawal")]
    NotReady {
        #[location]
        location: Location,
    },

    #[error("could not commit database transaction")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`locked_transaction`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LockedTransactionError {
    #[error("could not begin database transaction")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not acquire advisory lock")]
    Lock {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`load_dns_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadDnsResourceError {
    #[error("could not load managed DNS resource")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource {resource_id} not found")]
    NotFound {
        resource_id: Uuid,
        location: Location,
    },
}

/// Failure modes for [`fetch_dns_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum FetchDnsResourceError {
    #[error("could not fetch managed DNS resource")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource {resource_id} not found")]
    NotFound {
        resource_id: Uuid,
        location: Location,
    },
}

impl ManagedDns {
    #[tracing::instrument(skip_all, err)]
    pub(crate) async fn from_env() -> Result<Option<Self>, FromEnvError> {
        use FromEnvErrorCtx as Ctx;

        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let suffix = configured_dns_suffix().with_context(Ctx::suffix())?;
        let zone_id = std::env::var("CAUTION_APPS_DNS_ZONE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let Some(zone_id) = zone_id else {
            if environment == "production" {
                return Err(FromEnvError::ZoneIdRequired {
                    location: std::panic::Location::caller(),
                });
            }
            tracing::warn!("CAUTION_APPS_DNS_ZONE_ID is not set - managed app DNS is disabled");
            return Ok(None);
        };

        Ok(Some(Self {
            zone_id,
            suffix,
            api: Arc::new(AwsRoute53Api::from_environment().await),
        }))
    }

    #[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
    pub(crate) async fn publish_resource(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<DnsSnapshot, PublishError> {
        let started = tokio::time::Instant::now();
        loop {
            match self.publish_once(pool, resource_id).await {
                Ok(PublishProgress::Ready) => {
                    return Ok(DnsSnapshot {
                        status: "ready".to_string(),
                        error: None,
                    });
                }
                Ok(PublishProgress::Pending) if started.elapsed() < CHANGE_WAIT_TIMEOUT => {
                    tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
                }
                Ok(PublishProgress::Pending) => {
                    let error = PublishError::PublishTimeout {
                        resource_id,
                        location: std::panic::Location::caller(),
                    };
                    record_dns_error(pool, resource_id, "publishing", &error).await;
                    return Err(error);
                }
                Err(error) => {
                    record_dns_error(pool, resource_id, "publishing", &error).await;
                    return Err(error);
                }
            }
        }
    }

    #[tracing::instrument(skip_all, err)]
    async fn publish_once(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<PublishProgress, PublishError> {
        use PublishErrorCtx as Ctx;

        let mut tx = locked_transaction(pool, resource_id)
            .await
            .with_context(Ctx::transaction())?;
        let resource = load_dns_resource(&mut tx, resource_id)
            .await
            .with_context(Ctx::load())?;
        if resource.dns_status == "ready" {
            tx.commit().await.with_context(Ctx::commit())?;
            return Ok(PublishProgress::Ready);
        }
        if resource.dns_status != "publishing" {
            return Err(PublishError::NotPublishing {
                resource_id,
                location: std::panic::Location::caller(),
            });
        }

        if let Some(change_id) = resource.dns_change_id {
            if !self
                .api
                .change_is_insync(&change_id)
                .await
                .with_context(Ctx::insync())?
            {
                tx.commit().await.with_context(Ctx::commit())?;
                return Ok(PublishProgress::Pending);
            }
            sqlx::query(
                "UPDATE compute_resources
                 SET dns_status = 'ready', dns_change_id = NULL, dns_error = NULL,
                     dns_release_not_before = NULL, updated_at = NOW()
                 WHERE id = $1 AND dns_status = 'publishing'",
            )
            .bind(resource_id)
            .execute(&mut *tx)
            .await
            .with_context(Ctx::update())?;
            tx.commit().await.with_context(Ctx::commit())?;
            return Ok(PublishProgress::Ready);
        }

        let public_ip = resource.public_ip.ok_or_else(|| PublishError::NoPublicIp {
            resource_id,
            location: std::panic::Location::caller(),
        })?;
        let change_id = self
            .api
            .upsert_a(
                &self.zone_id,
                &managed_hostname_for_suffix(resource_id, &self.suffix),
                &public_ip,
                MANAGED_DNS_TTL_SECS,
            )
            .await
            .with_context(Ctx::upsert())?;
        sqlx::query(
            "UPDATE compute_resources
             SET dns_change_id = $1, dns_error = NULL, updated_at = NOW()
             WHERE id = $2 AND dns_status = 'publishing'",
        )
        .bind(change_id)
        .bind(resource_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::update())?;
        tx.commit().await.with_context(Ctx::commit())?;
        Ok(PublishProgress::Pending)
    }

    #[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
    pub(crate) async fn ensure_safe_to_release(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<(), WithdrawError> {
        use WithdrawErrorCtx as Ctx;

        let mut withdrawal_started = None;
        loop {
            let resource = fetch_dns_resource(pool, resource_id)
                .await
                .with_context(Ctx::fetch())?;
            match resource.dns_status.as_str() {
                "reserved" => return Ok(()),
                "publishing" => {
                    self.publish_resource(pool, resource_id)
                        .await
                        .with_context(Ctx::publish())?;
                    transition_to_withdrawing(pool, resource_id)
                        .await
                        .with_context(Ctx::transition())?;
                }
                "ready" => transition_to_withdrawing(pool, resource_id)
                    .await
                    .with_context(Ctx::transition())?,
                "withdrawing" => {
                    let started = withdrawal_started.get_or_insert_with(tokio::time::Instant::now);
                    match self.withdraw_once(pool, resource_id).await {
                        Ok(WithdrawalProgress::Safe) => return Ok(()),
                        Ok(WithdrawalProgress::Pending) => {
                            if started.elapsed() >= CHANGE_WAIT_TIMEOUT {
                                let error = WithdrawError::WithdrawTimeout {
                                    resource_id,
                                    location: std::panic::Location::caller(),
                                };
                                record_dns_error(pool, resource_id, "withdrawing", &error).await;
                                return Err(error);
                            }
                            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
                        }
                        Ok(WithdrawalProgress::Wait(duration)) => {
                            tokio::time::sleep(duration).await
                        }
                        Err(error) => {
                            record_dns_error(pool, resource_id, "withdrawing", &error).await;
                            return Err(error);
                        }
                    }
                }
                other => {
                    return Err(WithdrawError::InvalidStatus {
                        status: other.to_string(),
                        location: std::panic::Location::caller(),
                    });
                }
            }
        }
    }

    #[tracing::instrument(skip_all, err)]
    async fn withdraw_once(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<WithdrawalProgress, WithdrawError> {
        use WithdrawErrorCtx as Ctx;

        let mut tx = locked_transaction(pool, resource_id)
            .await
            .with_context(Ctx::transaction())?;
        let resource = load_dns_resource(&mut tx, resource_id)
            .await
            .with_context(Ctx::load())?;
        if resource.dns_status != "withdrawing" {
            return Err(WithdrawError::NotWithdrawing {
                resource_id,
                location: std::panic::Location::caller(),
            });
        }

        if let Some(release_at) = resource.dns_release_not_before {
            let now = Utc::now();
            tx.commit().await.with_context(Ctx::commit())?;
            return Ok(match drain_wait(release_at, now) {
                Some(wait) => WithdrawalProgress::Wait(wait),
                None => WithdrawalProgress::Safe,
            });
        }

        if let Some(change_id) = resource.dns_change_id {
            if !self
                .api
                .change_is_insync(&change_id)
                .await
                .with_context(Ctx::insync())?
            {
                tx.commit().await.with_context(Ctx::commit())?;
                return Ok(WithdrawalProgress::Pending);
            }
            let release_at = Utc::now() + ChronoDuration::seconds(MANAGED_DNS_TTL_SECS);
            sqlx::query(
                "UPDATE compute_resources
                 SET dns_change_id = NULL, dns_error = NULL, dns_release_not_before = $1,
                     updated_at = NOW()
                 WHERE id = $2 AND dns_status = 'withdrawing'",
            )
            .bind(release_at)
            .bind(resource_id)
            .execute(&mut *tx)
            .await
            .with_context(Ctx::update())?;
            tx.commit().await.with_context(Ctx::commit())?;
            return Ok(WithdrawalProgress::Wait(Duration::from_secs(
                MANAGED_DNS_TTL_SECS as u64,
            )));
        }

        let name = managed_hostname_for_suffix(resource_id, &self.suffix);
        let record = match self
            .api
            .get_a(&self.zone_id, &name)
            .await
            .with_context(Ctx::get())?
        {
            Some(record) => record,
            None => {
                // A DELETE may have reached Route53 before its change ID was persisted.
                // Re-publish the still-held EIP before deleting again so a mere absent
                // lookup can never authorize release.
                let public_ip = resource
                    .public_ip
                    .ok_or_else(|| WithdrawError::NoPublicIp {
                        resource_id,
                        location: std::panic::Location::caller(),
                    })?;
                let upsert_id = self
                    .api
                    .upsert_a(&self.zone_id, &name, &public_ip, MANAGED_DNS_TTL_SECS)
                    .await
                    .with_context(Ctx::upsert())?;
                self.wait_for_change(&upsert_id)
                    .await
                    .with_context(Ctx::wait())?;
                self.api
                    .get_a(&self.zone_id, &name)
                    .await
                    .with_context(Ctx::get())?
                    .ok_or_else(|| WithdrawError::StillAbsent {
                        resource_id,
                        location: std::panic::Location::caller(),
                    })?
            }
        };
        let change_id = self
            .api
            .delete_a(&self.zone_id, &name, &record)
            .await
            .with_context(Ctx::delete())?;
        sqlx::query(
            "UPDATE compute_resources
             SET dns_change_id = $1, dns_error = NULL, updated_at = NOW()
             WHERE id = $2 AND dns_status = 'withdrawing'",
        )
        .bind(change_id)
        .bind(resource_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::update())?;
        tx.commit().await.with_context(Ctx::commit())?;
        Ok(WithdrawalProgress::Pending)
    }

    #[tracing::instrument(skip_all, err)]
    async fn wait_for_change(&self, change_id: &str) -> Result<(), WaitForChangeError> {
        use WaitForChangeErrorCtx as Ctx;

        let started = tokio::time::Instant::now();
        loop {
            if self
                .api
                .change_is_insync(change_id)
                .await
                .with_context(Ctx::insync())?
            {
                return Ok(());
            }
            if started.elapsed() >= CHANGE_WAIT_TIMEOUT {
                return Err(WaitForChangeError::Timeout {
                    location: std::panic::Location::caller(),
                });
            }
            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
        }
    }
}

#[tracing::instrument(skip_all)]
pub(crate) fn managed_hostname(resource_id: Uuid) -> String {
    let suffix = configured_dns_suffix().expect("managed DNS suffix was validated at startup");
    managed_hostname_for_suffix(resource_id, &suffix)
}

#[tracing::instrument(skip_all, err)]
fn configured_dns_suffix() -> Result<String, NormalizeDnsSuffixError> {
    normalize_dns_suffix(
        &std::env::var("CAUTION_APPS_DNS_SUFFIX")
            .unwrap_or_else(|_| DEFAULT_MANAGED_DNS_SUFFIX.to_string()),
    )
}

#[tracing::instrument(skip_all, err)]
fn normalize_dns_suffix(value: &str) -> Result<String, NormalizeDnsSuffixError> {
    let suffix = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !suffix.is_empty()
        && suffix.len() <= 253
        && suffix.split('.').count() >= 2
        && suffix.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !valid {
        return Err(NormalizeDnsSuffixError::Invalid {
            location: std::panic::Location::caller(),
        });
    }
    Ok(suffix)
}

fn managed_hostname_for_suffix(resource_id: Uuid, suffix: &str) -> String {
    resource_id.as_hyphenated().to_string() + "." + suffix
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn dns_snapshot(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<DnsSnapshot, DnsSnapshotError> {
    use DnsSnapshotErrorCtx as Ctx;

    let (status, error): (String, Option<String>) =
        sqlx::query_as("SELECT dns_status, dns_error FROM compute_resources WHERE id = $1")
            .bind(resource_id)
            .fetch_one(pool)
            .await
            .with_context(Ctx::query())?;
    Ok(DnsSnapshot { status, error })
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn begin_termination(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<(), BeginTerminationError> {
    use BeginTerminationErrorCtx as Ctx;

    let result = sqlx::query(
        "UPDATE compute_resources
         SET state = 'terminating',
             dns_status = CASE WHEN dns_status = 'ready' THEN 'withdrawing' ELSE dns_status END,
             dns_error = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_error END,
             dns_change_id = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_change_id END,
             dns_release_not_before = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_release_not_before END,
             updated_at = NOW()
         WHERE id = $1 AND destroyed_at IS NULL AND state <> 'pending'",
    )
    .bind(resource_id)
    .execute(pool)
    .await
    .with_context(Ctx::query())?;
    if result.rows_affected() == 0 {
        let state: Option<(String, Option<DateTime<Utc>>)> =
            sqlx::query_as("SELECT state::text, destroyed_at FROM compute_resources WHERE id = $1")
                .bind(resource_id)
                .fetch_optional(pool)
                .await
                .with_context(Ctx::query())?;
        if state.is_some_and(|(state, destroyed_at)| state == "pending" && destroyed_at.is_none()) {
            return Err(BeginTerminationError::Deploying {
                location: std::panic::Location::caller(),
            });
        }
        return Err(BeginTerminationError::Gone {
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn begin_owned_deploy_rollback(
    pool: &PgPool,
    resource_id: Uuid,
    organization_id: Uuid,
    deploy_attempt_id: Uuid,
    region: &str,
) -> Result<bool, BeginOwnedDeployRollbackError> {
    use BeginOwnedDeployRollbackErrorCtx as Ctx;

    let result = sqlx::query(
        "UPDATE compute_resources
         SET state = 'terminating', region = $1,
             dns_status = CASE WHEN dns_status = 'ready' THEN 'withdrawing' ELSE dns_status END,
             dns_error = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_error END,
             dns_change_id = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_change_id END,
             dns_release_not_before = CASE WHEN dns_status = 'ready' THEN NULL ELSE dns_release_not_before END,
             updated_at = NOW()
         WHERE id = $2 AND organization_id = $3 AND destroyed_at IS NULL
           AND state = 'pending' AND deploy_attempt_id = $4",
    )
    .bind(region)
    .bind(resource_id)
    .bind(organization_id)
    .bind(deploy_attempt_id)
    .execute(pool)
    .await
    .with_context(Ctx::query())?;
    if result.rows_affected() == 1 {
        return Ok(true);
    }

    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM compute_resources
             WHERE id = $1 AND organization_id = $2 AND destroyed_at IS NULL
               AND state = 'terminating' AND deploy_attempt_id = $3
         )",
    )
    .bind(resource_id)
    .bind(organization_id)
    .bind(deploy_attempt_id)
    .fetch_one(pool)
    .await
    .with_context(Ctx::query())
}

#[tracing::instrument(skip_all, err)]
async fn transition_to_withdrawing(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<(), TransitionToWithdrawingError> {
    use TransitionToWithdrawingErrorCtx as Ctx;

    let mut tx = locked_transaction(pool, resource_id)
        .await
        .with_context(Ctx::transaction())?;
    let result = sqlx::query(
        "UPDATE compute_resources
         SET dns_status = 'withdrawing', dns_error = NULL, dns_change_id = NULL,
             dns_release_not_before = NULL, updated_at = NOW()
         WHERE id = $1 AND state = 'terminating' AND dns_status = 'ready'",
    )
    .bind(resource_id)
    .execute(&mut *tx)
    .await
    .with_context(Ctx::update())?;
    if result.rows_affected() == 0 {
        return Err(TransitionToWithdrawingError::NotReady {
            location: std::panic::Location::caller(),
        });
    }
    tx.commit().await.with_context(Ctx::commit())?;
    Ok(())
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn locked_transaction<'a>(
    pool: &'a PgPool,
    resource_id: Uuid,
) -> Result<Transaction<'a, Postgres>, LockedTransactionError> {
    use LockedTransactionErrorCtx as Ctx;

    let mut tx = pool.begin().await.with_context(Ctx::begin())?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(resource_id.to_string())
        .execute(&mut *tx)
        .await
        .with_context(Ctx::lock())?;
    Ok(tx)
}

#[tracing::instrument(skip_all, err)]
async fn load_dns_resource(
    tx: &mut Transaction<'_, Postgres>,
    resource_id: Uuid,
) -> Result<DnsResource, LoadDnsResourceError> {
    use LoadDnsResourceErrorCtx as Ctx;

    sqlx::query_as::<
        _,
        (
            Option<String>,
            String,
            Option<String>,
            Option<DateTime<Utc>>,
        ),
    >(
        "SELECT public_ip, dns_status, dns_change_id, dns_release_not_before
         FROM compute_resources WHERE id = $1",
    )
    .bind(resource_id)
    .fetch_optional(&mut **tx)
    .await
    .with_context(Ctx::query())?
    .map(
        |(public_ip, dns_status, dns_change_id, dns_release_not_before)| DnsResource {
            public_ip,
            dns_status,
            dns_change_id,
            dns_release_not_before,
        },
    )
    .ok_or_else(|| LoadDnsResourceError::NotFound {
        resource_id,
        location: std::panic::Location::caller(),
    })
}

#[tracing::instrument(skip_all, err)]
async fn fetch_dns_resource(
    pool: &PgPool,
    resource_id: Uuid,
) -> Result<DnsResource, FetchDnsResourceError> {
    use FetchDnsResourceErrorCtx as Ctx;

    sqlx::query_as::<
        _,
        (
            Option<String>,
            String,
            Option<String>,
            Option<DateTime<Utc>>,
        ),
    >(
        "SELECT public_ip, dns_status, dns_change_id, dns_release_not_before
         FROM compute_resources WHERE id = $1",
    )
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::query())?
    .map(
        |(public_ip, dns_status, dns_change_id, dns_release_not_before)| DnsResource {
            public_ip,
            dns_status,
            dns_change_id,
            dns_release_not_before,
        },
    )
    .ok_or_else(|| FetchDnsResourceError::NotFound {
        resource_id,
        location: std::panic::Location::caller(),
    })
}

async fn record_dns_error(
    pool: &PgPool,
    resource_id: Uuid,
    status: &str,
    error: &(dyn std::error::Error + Send + Sync + 'static),
) {
    let message = sanitize_error(error);
    if let Err(update_error) = sqlx::query(
        "UPDATE compute_resources SET dns_error = $1, updated_at = NOW()
         WHERE id = $2 AND dns_status = $3",
    )
    .bind(message)
    .bind(resource_id)
    .bind(status)
    .execute(pool)
    .await
    {
        tracing::error!(resource_id = %resource_id, error = %update_error, "failed to persist managed DNS error");
    }
}

pub(crate) fn sanitize_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        parts.push(source.to_string());
        current = source.source();
    }
    let single_line = parts.join(": ").replace(['\r', '\n'], " ");
    single_line.chars().take(500).collect()
}

fn drain_wait(release_at: DateTime<Utc>, now: DateTime<Utc>) -> Option<Duration> {
    (release_at > now).then(|| {
        (release_at - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MANAGED_DNS_SUFFIX, drain_wait, managed_hostname_for_suffix, normalize_dns_suffix,
        sanitize_error,
    };
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn hostname_is_derived_from_lowercase_resource_uuid() {
        let id = Uuid::parse_str("A0A13A1B-8C7F-4F3B-AB74-E662FF31A982").unwrap();
        assert_eq!(
            managed_hostname_for_suffix(id, DEFAULT_MANAGED_DNS_SUFFIX),
            "a0a13a1b-8c7f-4f3b-ab74-e662ff31a982.apps.caution.sh"
        );
    }

    #[test]
    fn custom_suffix_is_normalized_and_validated() {
        let id = Uuid::nil();
        assert_eq!(
            normalize_dns_suffix(" Apps.APOSDW.Space. ").unwrap(),
            "apps.aposdw.space"
        );
        assert_eq!(
            managed_hostname_for_suffix(id, "apps.aposdw.space"),
            "00000000-0000-0000-0000-000000000000.apps.aposdw.space"
        );
        assert!(normalize_dns_suffix("not-a-suffix").is_err());
        assert!(normalize_dns_suffix("-apps.aposdw.space").is_err());
    }

    #[test]
    fn persisted_errors_are_single_line_and_bounded() {
        let message = ["first\n", &"x".repeat(600)].concat();
        let error: Box<dyn std::error::Error + Send + Sync + 'static> = message.into();
        let sanitized = sanitize_error(&*error);
        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized.chars().count(), 500);
    }

    #[test]
    fn eip_release_waits_until_the_persisted_ttl_deadline() {
        let now = Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap();
        let deadline = now + ChronoDuration::seconds(60);

        assert_eq!(drain_wait(deadline, now), Some(Duration::from_secs(60)));
        assert_eq!(drain_wait(deadline, deadline), None);
        assert_eq!(
            drain_wait(deadline, deadline + ChronoDuration::seconds(1)),
            None
        );
    }
}

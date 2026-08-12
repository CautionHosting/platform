// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) const MANAGED_DNS_SUFFIX: &str = "apps.caution.sh";
pub(crate) const MANAGED_DNS_TTL_SECS: i64 = 60;
const CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const CHANGE_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ARecordSet {
    ttl: i64,
    values: Vec<String>,
}

#[async_trait]
trait Route53Api: Send + Sync {
    async fn upsert_a(&self, zone_id: &str, name: &str, ip: &str, ttl: i64) -> Result<String>;
    async fn delete_a(&self, zone_id: &str, name: &str, record: &ARecordSet) -> Result<String>;
    async fn get_a(&self, zone_id: &str, name: &str) -> Result<Option<ARecordSet>>;
    async fn change_is_insync(&self, change_id: &str) -> Result<bool>;
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

    fn rrset(name: &str, ttl: i64, values: &[String]) -> Result<ResourceRecordSet> {
        let records = values
            .iter()
            .map(|value| ResourceRecord::builder().value(value).build())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ResourceRecordSet::builder()
            .name(name)
            .r#type(RrType::A)
            .ttl(ttl)
            .set_resource_records(Some(records))
            .build()?)
    }

    async fn change(
        &self,
        zone_id: &str,
        action: ChangeAction,
        rrset: ResourceRecordSet,
    ) -> Result<String> {
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()?;
        let batch = ChangeBatch::builder().changes(change).build()?;
        let output = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .context("Route53 record change failed")?;

        Ok(output
            .change_info()
            .context("Route53 record change returned no change information")?
            .id()
            .to_string())
    }
}

#[async_trait]
impl Route53Api for AwsRoute53Api {
    async fn upsert_a(&self, zone_id: &str, name: &str, ip: &str, ttl: i64) -> Result<String> {
        let rrset = Self::rrset(name, ttl, &[ip.to_string()])?;
        self.change(zone_id, ChangeAction::Upsert, rrset).await
    }

    async fn delete_a(&self, zone_id: &str, name: &str, record: &ARecordSet) -> Result<String> {
        let rrset = Self::rrset(name, record.ttl, &record.values)?;
        self.change(zone_id, ChangeAction::Delete, rrset).await
    }

    async fn get_a(&self, zone_id: &str, name: &str) -> Result<Option<ARecordSet>> {
        let output = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(zone_id)
            .start_record_name(name)
            .start_record_type(RrType::A)
            .max_items(1)
            .send()
            .await
            .context("Route53 record lookup failed")?;

        let Some(record) = output.resource_record_sets().first() else {
            return Ok(None);
        };
        if record.name().trim_end_matches('.') != name.trim_end_matches('.')
            || record.r#type() != &RrType::A
        {
            return Ok(None);
        }

        let ttl = record
            .ttl()
            .ok_or_else(|| anyhow!("managed Route53 A record has no TTL"))?;
        let values = record
            .resource_records()
            .iter()
            .map(|record| record.value().to_string())
            .collect();
        Ok(Some(ARecordSet { ttl, values }))
    }

    async fn change_is_insync(&self, change_id: &str) -> Result<bool> {
        let output = self
            .client
            .get_change()
            .id(change_id)
            .send()
            .await
            .context("Route53 change status lookup failed")?;
        Ok(output
            .change_info()
            .context("Route53 change lookup returned no change information")?
            .status()
            == &ChangeStatus::Insync)
    }
}

#[derive(Clone)]
pub(crate) struct ManagedDns {
    zone_id: String,
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

impl ManagedDns {
    pub(crate) async fn from_env() -> Result<Option<Self>> {
        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let zone_id = std::env::var("CAUTION_APPS_DNS_ZONE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let Some(zone_id) = zone_id else {
            if environment == "production" {
                bail!("CAUTION_APPS_DNS_ZONE_ID must be set in production");
            }
            tracing::warn!("CAUTION_APPS_DNS_ZONE_ID is not set - managed app DNS is disabled");
            return Ok(None);
        };

        Ok(Some(Self {
            zone_id,
            api: Arc::new(AwsRoute53Api::from_environment().await),
        }))
    }

    pub(crate) async fn publish_resource(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<DnsSnapshot> {
        let started = tokio::time::Instant::now();
        loop {
            match self.publish_once(pool, resource_id).await {
                Ok(PublishProgress::Ready) => return dns_snapshot(pool, resource_id).await,
                Ok(PublishProgress::Pending) if started.elapsed() < CHANGE_WAIT_TIMEOUT => {
                    tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
                }
                Ok(PublishProgress::Pending) => {
                    let error = anyhow!("Route53 UPSERT did not reach INSYNC within 120 seconds");
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

    async fn publish_once(&self, pool: &PgPool, resource_id: Uuid) -> Result<PublishProgress> {
        let mut tx = locked_transaction(pool, resource_id).await?;
        let resource = load_dns_resource(&mut tx, resource_id).await?;
        if resource.dns_status == "ready" {
            tx.commit().await?;
            return Ok(PublishProgress::Ready);
        }
        if resource.dns_status != "publishing" {
            bail!("resource is not awaiting DNS publication");
        }

        if let Some(change_id) = resource.dns_change_id {
            if !self.api.change_is_insync(&change_id).await? {
                tx.commit().await?;
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
            .await?;
            tx.commit().await?;
            return Ok(PublishProgress::Ready);
        }

        let public_ip = resource
            .public_ip
            .ok_or_else(|| anyhow!("cannot publish managed DNS without a public IP"))?;
        let change_id = self
            .api
            .upsert_a(
                &self.zone_id,
                &managed_hostname(resource_id),
                &public_ip,
                MANAGED_DNS_TTL_SECS,
            )
            .await?;
        sqlx::query(
            "UPDATE compute_resources
             SET dns_change_id = $1, dns_error = NULL, updated_at = NOW()
             WHERE id = $2 AND dns_status = 'publishing'",
        )
        .bind(change_id)
        .bind(resource_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PublishProgress::Pending)
    }

    pub(crate) async fn ensure_safe_to_release(
        &self,
        pool: &PgPool,
        resource_id: Uuid,
    ) -> Result<()> {
        let mut withdrawal_started = None;
        loop {
            let resource = fetch_dns_resource(pool, resource_id).await?;
            match resource.dns_status.as_str() {
                "reserved" => return Ok(()),
                "publishing" => {
                    self.publish_resource(pool, resource_id).await?;
                    transition_to_withdrawing(pool, resource_id).await?;
                }
                "ready" => transition_to_withdrawing(pool, resource_id).await?,
                "withdrawing" => {
                    let started = withdrawal_started.get_or_insert_with(tokio::time::Instant::now);
                    match self.withdraw_once(pool, resource_id).await {
                        Ok(WithdrawalProgress::Safe) => return Ok(()),
                        Ok(WithdrawalProgress::Pending) => {
                            if started.elapsed() >= CHANGE_WAIT_TIMEOUT {
                                let error = anyhow!(
                                    "Route53 DELETE did not reach INSYNC within 120 seconds"
                                );
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
                other => bail!("invalid managed DNS status {other}"),
            }
        }
    }

    async fn withdraw_once(&self, pool: &PgPool, resource_id: Uuid) -> Result<WithdrawalProgress> {
        let mut tx = locked_transaction(pool, resource_id).await?;
        let resource = load_dns_resource(&mut tx, resource_id).await?;
        if resource.dns_status != "withdrawing" {
            bail!("resource is not awaiting DNS withdrawal");
        }

        if let Some(release_at) = resource.dns_release_not_before {
            let now = Utc::now();
            tx.commit().await?;
            return Ok(match drain_wait(release_at, now) {
                Some(wait) => WithdrawalProgress::Wait(wait),
                None => WithdrawalProgress::Safe,
            });
        }

        if let Some(change_id) = resource.dns_change_id {
            if !self.api.change_is_insync(&change_id).await? {
                tx.commit().await?;
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
            .await?;
            tx.commit().await?;
            return Ok(WithdrawalProgress::Wait(Duration::from_secs(
                MANAGED_DNS_TTL_SECS as u64,
            )));
        }

        let name = managed_hostname(resource_id);
        let record = match self.api.get_a(&self.zone_id, &name).await? {
            Some(record) => record,
            None => {
                // A DELETE may have reached Route53 before its change ID was persisted.
                // Re-publish the still-held EIP before deleting again so a mere absent
                // lookup can never authorize release.
                let public_ip = resource.public_ip.ok_or_else(|| {
                    anyhow!("cannot prove DNS withdrawal without the retained public IP")
                })?;
                let upsert_id = self
                    .api
                    .upsert_a(&self.zone_id, &name, &public_ip, MANAGED_DNS_TTL_SECS)
                    .await?;
                self.wait_for_change(&upsert_id).await?;
                self.api.get_a(&self.zone_id, &name).await?.ok_or_else(|| {
                    anyhow!("managed A record is still absent after conservative UPSERT")
                })?
            }
        };
        let change_id = self.api.delete_a(&self.zone_id, &name, &record).await?;
        sqlx::query(
            "UPDATE compute_resources
             SET dns_change_id = $1, dns_error = NULL, updated_at = NOW()
             WHERE id = $2 AND dns_status = 'withdrawing'",
        )
        .bind(change_id)
        .bind(resource_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(WithdrawalProgress::Pending)
    }

    async fn wait_for_change(&self, change_id: &str) -> Result<()> {
        let started = tokio::time::Instant::now();
        loop {
            if self.api.change_is_insync(change_id).await? {
                return Ok(());
            }
            if started.elapsed() >= CHANGE_WAIT_TIMEOUT {
                bail!("Route53 change did not reach INSYNC within 120 seconds");
            }
            tokio::time::sleep(CHANGE_POLL_INTERVAL).await;
        }
    }
}

pub(crate) fn managed_hostname(resource_id: Uuid) -> String {
    resource_id.as_hyphenated().to_string() + "." + MANAGED_DNS_SUFFIX
}

pub(crate) async fn dns_snapshot(pool: &PgPool, resource_id: Uuid) -> Result<DnsSnapshot> {
    let (status, error): (String, Option<String>) =
        sqlx::query_as("SELECT dns_status, dns_error FROM compute_resources WHERE id = $1")
            .bind(resource_id)
            .fetch_one(pool)
            .await?;
    Ok(DnsSnapshot { status, error })
}

pub(crate) async fn mark_publishing(pool: &PgPool, resource_id: Uuid) -> Result<()> {
    let result = sqlx::query(
        "UPDATE compute_resources
         SET dns_status = 'publishing', dns_error = NULL, dns_change_id = NULL,
             dns_release_not_before = NULL, updated_at = NOW()
         WHERE id = $1 AND public_ip IS NOT NULL AND state = 'running'",
    )
    .bind(resource_id)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        bail!("resource lifecycle changed before managed DNS publication");
    }
    Ok(())
}

pub(crate) async fn begin_termination(pool: &PgPool, resource_id: Uuid) -> Result<()> {
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
    .await?;
    if result.rows_affected() == 0 {
        bail!("resource is deploying or no longer exists");
    }
    Ok(())
}

async fn transition_to_withdrawing(pool: &PgPool, resource_id: Uuid) -> Result<()> {
    let mut tx = locked_transaction(pool, resource_id).await?;
    let result = sqlx::query(
        "UPDATE compute_resources
         SET dns_status = 'withdrawing', dns_error = NULL, dns_change_id = NULL,
             dns_release_not_before = NULL, updated_at = NOW()
         WHERE id = $1 AND state = 'terminating' AND dns_status = 'ready'",
    )
    .bind(resource_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        bail!("resource DNS is not ready for withdrawal");
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn locked_transaction<'a>(
    pool: &'a PgPool,
    resource_id: Uuid,
) -> Result<Transaction<'a, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(resource_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn load_dns_resource(
    tx: &mut Transaction<'_, Postgres>,
    resource_id: Uuid,
) -> Result<DnsResource> {
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
    .await?
    .map(
        |(public_ip, dns_status, dns_change_id, dns_release_not_before)| DnsResource {
            public_ip,
            dns_status,
            dns_change_id,
            dns_release_not_before,
        },
    )
    .ok_or_else(|| anyhow!("resource {resource_id} not found"))
}

async fn fetch_dns_resource(pool: &PgPool, resource_id: Uuid) -> Result<DnsResource> {
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
    .await?
    .map(
        |(public_ip, dns_status, dns_change_id, dns_release_not_before)| DnsResource {
            public_ip,
            dns_status,
            dns_change_id,
            dns_release_not_before,
        },
    )
    .ok_or_else(|| anyhow!("resource {resource_id} not found"))
}

async fn record_dns_error(pool: &PgPool, resource_id: Uuid, status: &str, error: &anyhow::Error) {
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

fn sanitize_error(error: &anyhow::Error) -> String {
    let single_line = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
        .replace(['\r', '\n'], " ");
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
    use super::{drain_wait, managed_hostname, sanitize_error};
    use anyhow::anyhow;
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn hostname_is_derived_from_lowercase_resource_uuid() {
        let id = Uuid::parse_str("A0A13A1B-8C7F-4F3B-AB74-E662FF31A982").unwrap();
        assert_eq!(
            managed_hostname(id),
            "a0a13a1b-8c7f-4f3b-ab74-e662ff31a982.apps.caution.sh"
        );
    }

    #[test]
    fn persisted_errors_are_single_line_and_bounded() {
        let error = anyhow!(["first\n", &"x".repeat(600)].concat());
        let sanitized = sanitize_error(&error);
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

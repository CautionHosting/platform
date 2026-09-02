// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

mod cost;
mod display;
mod inventory;
mod reconcile;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::Client as StsClient;
use chrono::Utc;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use uuid::Uuid;

use crate::{db::Database, model::ResourceSummary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsSection {
    AppHosts,
    Builders,
    Storage,
    Drift,
    Costs,
    Byoc,
}

impl AwsSection {
    pub const ALL: [Self; 6] = [
        Self::AppHosts,
        Self::Builders,
        Self::Storage,
        Self::Drift,
        Self::Costs,
        Self::Byoc,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::AppHosts => "App hosts",
            Self::Builders => "Builders",
            Self::Storage => "Storage and IPs",
            Self::Drift => "Drift",
            Self::Costs => "Costs",
            Self::Byoc => "BYOC",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAction {
    None,
    Section(AwsSection),
    Resource(ResourceSummary),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDisplayRow {
    pub kind: String,
    pub name: String,
    pub details: String,
    pub action: AwsAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsOverviewMetadata {
    pub account: String,
    pub principal: String,
    pub regions: String,
    pub updated: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSnapshot {
    pub metadata: AwsOverviewMetadata,
    pub overview: Vec<AwsDisplayRow>,
    pub app_hosts: Vec<AwsDisplayRow>,
    pub builders: Vec<AwsDisplayRow>,
    pub storage: Vec<AwsDisplayRow>,
    pub drift: Vec<AwsDisplayRow>,
    pub costs: Vec<AwsDisplayRow>,
    pub byoc: Vec<AwsDisplayRow>,
    pub stale_reason: Option<String>,
    pub identity_available: bool,
    pub inventory_available: bool,
    pub costs_available: bool,
}

impl AwsSnapshot {
    pub fn rows(&self, section: AwsSection) -> Vec<AwsDisplayRow> {
        match section {
            AwsSection::AppHosts => &self.app_hosts,
            AwsSection::Builders => &self.builders,
            AwsSection::Storage => &self.storage,
            AwsSection::Drift => &self.drift,
            AwsSection::Costs => &self.costs,
            AwsSection::Byoc => &self.byoc,
        }
        .clone()
    }

    pub fn mark_stale(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.stale_reason = Some(reason.clone());
        mark_metadata_stale(&mut self.metadata, &reason);
    }

    pub fn merge_refresh(&self, mut next: Self) -> Self {
        let retain_identity = !next.identity_available && self.identity_available;
        let retain_inventory = !next.inventory_available && self.inventory_available;
        let retain_costs = !next.costs_available && self.costs_available;
        if retain_identity {
            next.metadata.account.clone_from(&self.metadata.account);
            next.metadata.principal.clone_from(&self.metadata.principal);
            next.identity_available = true;
        }
        if retain_inventory {
            next.app_hosts = self.app_hosts.clone();
            next.builders = self.builders.clone();
            next.storage = self.storage.clone();
            next.drift = self.drift.clone();
            next.metadata.regions.clone_from(&self.metadata.regions);
            for section in [
                AwsSection::AppHosts,
                AwsSection::Builders,
                AwsSection::Storage,
                AwsSection::Drift,
            ] {
                preserve_overview_row(self, &mut next, |row| {
                    row.action == AwsAction::Section(section)
                });
            }
            next.inventory_available = true;
        }
        if retain_costs {
            next.costs = self.costs.clone();
            preserve_overview_row(self, &mut next, |row| {
                row.action == AwsAction::Section(AwsSection::Costs)
            });
            next.costs_available = true;
        }
        if retain_identity || retain_inventory || retain_costs {
            let reason = "partial refresh failed; retained previous data";
            next.stale_reason = Some(reason.to_string());
            mark_metadata_stale(&mut next.metadata, reason);
        }
        next
    }
}

fn mark_metadata_stale(metadata: &mut AwsOverviewMetadata, reason: &str) {
    metadata.status = "stale".to_string();
    let updated = metadata
        .updated
        .split_once(" · ")
        .map_or(metadata.updated.as_str(), |(updated, _)| updated);
    metadata.updated = format!("{updated} · {reason}");
}

fn preserve_overview_row(
    previous: &AwsSnapshot,
    next: &mut AwsSnapshot,
    predicate: impl Fn(&AwsDisplayRow) -> bool,
) {
    let Some(mut preserved) = previous.overview.iter().find(|row| predicate(row)).cloned() else {
        return;
    };
    preserved.details = format!("warning · stale · {}", strip_status(&preserved.details));
    if let Some(row) = next.overview.iter_mut().find(|row| predicate(row)) {
        *row = preserved;
    } else {
        next.overview.push(preserved);
    }
}

fn strip_status(details: &str) -> &str {
    let details = details.split_once(" · ").map_or(details, |(_, rest)| rest);
    details.strip_prefix("stale · ").unwrap_or(details)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountIdentity {
    account: String,
    principal: String,
}

pub async fn load_snapshot(database: &Database) -> Result<AwsSnapshot, LoadSnapshotError> {
    use LoadSnapshotErrorCtx as Ctx;

    let region = RegionProviderChain::default_provider().or_else("us-west-2");
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let sts = StsClient::new(&config);
    let cost_client = aws_sdk_costexplorer::Client::new(&config);
    let today = Utc::now().date_naive();
    let (database_state, identity, inventory, costs) = tokio::join!(
        database.load_aws_state(),
        fetch_identity(&sts),
        inventory::fetch_inventory(&config),
        cost::fetch_costs(&cost_client, today),
    );
    let database_state = database_state.with_context(Ctx::database())?;
    Ok(reconcile::build_snapshot(
        database_state,
        identity,
        inventory,
        costs,
        Utc::now(),
    ))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LoadSnapshotError {
    #[error("failed to load Platform state for the AWS snapshot [{location:?}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn fetch_identity(client: &StsClient) -> Result<AccountIdentity, FetchIdentityError> {
    use FetchIdentityErrorCtx as Ctx;

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.get_caller_identity().send(),
    )
    .await
    .with_context(Ctx::request())?
    .with_context(Ctx::request())?;
    let account = output.account().ok_or(FetchIdentityError::MissingAccount {
        location: std::panic::Location::caller(),
    })?;
    let principal = output
        .arn()
        .and_then(|arn| arn.rsplit(['/', ':']).next())
        .unwrap_or("unknown");
    Ok(AccountIdentity {
        account: account.to_string(),
        principal: principal.to_string(),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
enum FetchIdentityError {
    #[error("failed to identify the AWS caller [{location:?}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("AWS did not return an account ID [{location:?}]")]
    MissingAccount {
        #[location]
        location: Location,
    },
}

fn resource_summary(kind: crate::model::ResourceKind, id: Uuid, label: String) -> ResourceSummary {
    ResourceSummary {
        kind,
        id,
        label,
        context: None,
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

mod cost;
mod display;
mod inventory;
mod reconcile;
mod report;

pub(crate) use inventory::AwsInstance;
pub use report::{
    FindingReport, FindingSeverity, FindingsCoverage, FindingsReport, load_findings_report,
};

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::Client as StsClient;
use chrono::Utc;
use drift_detector::drift::DriftSeverity;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use uuid::Uuid;

use crate::{
    db::Database,
    model::{ResourceRef, ResourceSummary},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsSection {
    AppHosts,
    Builders,
    Storage,
    Findings,
    Costs,
    Byoc,
}

impl AwsSection {
    pub const ALL: [Self; 6] = [
        Self::AppHosts,
        Self::Builders,
        Self::Storage,
        Self::Findings,
        Self::Costs,
        Self::Byoc,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::AppHosts => "App hosts",
            Self::Builders => "Builders",
            Self::Storage => "Storage and IPs",
            Self::Findings => "Findings",
            Self::Costs => "Costs",
            Self::Byoc => "BYOC",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingKind {
    ExpectedHostAbsent,
    HostForTerminatedApp,
    UnexpectedHost,
    StateMismatch,
    UntrackedHost,
    LinkMismatch,
    AmbiguousAssociation,
    InvalidAccountMapping,
    AccountMismatch,
    OrphanBuilder,
}

impl FindingKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExpectedHostAbsent => "expected_host_absent",
            Self::HostForTerminatedApp => "host_for_terminated_app",
            Self::UnexpectedHost => "unexpected_host",
            Self::StateMismatch => "state_mismatch",
            Self::UntrackedHost => "untracked_host",
            Self::LinkMismatch => "link_mismatch",
            Self::AmbiguousAssociation => "ambiguous_association",
            Self::InvalidAccountMapping => "invalid_account_mapping",
            Self::AccountMismatch => "account_mismatch",
            Self::OrphanBuilder => "orphan_builder",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ExpectedHostAbsent => "App expects EC2; none observed",
            Self::HostForTerminatedApp => "EC2 linked to terminated app",
            Self::UnexpectedHost => "EC2 present for inactive app",
            Self::StateMismatch => "Platform/AWS states differ",
            Self::UntrackedHost => "EC2 has no Platform match",
            Self::LinkMismatch => "EC2 association differs",
            Self::AmbiguousAssociation => "Multiple Platform records claim EC2",
            Self::InvalidAccountMapping => "Invalid provider account mapping",
            Self::AccountMismatch => "Provider account mismatch",
            Self::OrphanBuilder => "Orphan builder",
        }
    }

    pub const fn next_step(self) -> &'static str {
        match self {
            Self::ExpectedHostAbsent | Self::StateMismatch => {
                "Verify the Platform record and the expected EC2 instance."
            }
            Self::HostForTerminatedApp | Self::UnexpectedHost => {
                "Confirm whether the EC2 instance should still exist before taking action."
            }
            Self::UntrackedHost => "Identify the owner from AWS tags before taking action.",
            Self::LinkMismatch => "Compare the Platform host ID with the AWS resource tags.",
            Self::AmbiguousAssociation => {
                "Resolve the duplicate Platform host ownership before taking action."
            }
            Self::InvalidAccountMapping | Self::AccountMismatch => {
                "Verify the Platform provider account before changing either resource."
            }
            Self::OrphanBuilder => "Confirm the build is inactive before removing the builder.",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsFinding {
    pub severity: DriftSeverity,
    pub kind: FindingKind,
    pub subject: String,
    pub platform: String,
    pub aws: String,
    pub scope: Option<String>,
    pub host_id: Option<String>,
    pub resources: Vec<ResourceSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FindingKey {
    kind: FindingKind,
    host_id: Option<String>,
    resources: Vec<ResourceRef>,
    fallback_subject: Option<String>,
}

impl AwsFinding {
    pub(crate) fn key(&self) -> FindingKey {
        let mut resources = self
            .resources
            .iter()
            .map(ResourceSummary::reference)
            .collect::<Vec<_>>();
        resources.sort_unstable_by_key(|resource| (resource.kind as u8, resource.id));
        resources.dedup();
        let fallback_subject =
            (self.host_id.is_none() && resources.is_empty()).then(|| self.subject.clone());
        FindingKey {
            kind: self.kind,
            host_id: self.host_id.clone(),
            resources,
            fallback_subject,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AwsHostPlatform {
    pub resource: ResourceSummary,
    pub state: String,
    pub expected_host: Option<String>,
    pub account: Option<String>,
    pub relation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsHost {
    pub(crate) account: Option<String>,
    pub(crate) instance: AwsInstance,
    pub(crate) platform: Option<AwsHostPlatform>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsAction {
    None,
    Section(AwsSection),
    Host(String),
    Resource(ResourceSummary),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDisplayRow {
    pub kind: String,
    pub name: String,
    pub details: String,
    pub action: AwsAction,
}

pub(crate) fn is_cost_summary(row: &AwsDisplayRow) -> bool {
    matches!(row.kind.as_str(), "MTD" | "FORECAST")
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
    pub(crate) hosts: Vec<AwsHost>,
    pub storage: Vec<AwsDisplayRow>,
    pub findings: Vec<AwsFinding>,
    pub costs: Vec<AwsDisplayRow>,
    pub(crate) cost_snapshot: cost::CostSnapshot,
    pub byoc: Vec<AwsDisplayRow>,
    pub stale_reason: Option<String>,
    pub identity_available: bool,
    /// The inventory fetch returned data, even if some regions failed.
    pub inventory_available: bool,
    /// Every inventory component succeeded in every region.
    pub inventory_complete: bool,
    /// At least one regional EC2 instance scan succeeded.
    pub instances_available: bool,
    /// Every enabled region returned its EC2 instance inventory.
    pub instances_complete: bool,
    pub costs_available: bool,
}

impl AwsSnapshot {
    pub fn rows(&self, section: AwsSection) -> Vec<AwsDisplayRow> {
        match section {
            AwsSection::AppHosts => &self.app_hosts,
            AwsSection::Builders => &self.builders,
            AwsSection::Storage => &self.storage,
            AwsSection::Findings => return Vec::new(),
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
        // Reconciliation is account-scoped. Without a fresh STS identity we
        // cannot safely combine new inventory with Platform expectations, so
        // retain the last internally consistent inventory/findings snapshot.
        let retain_inventory = self.inventory_available
            && (!next.inventory_available || (!next.identity_available && self.identity_available));
        let retain_instances = self.instances_available
            && (!next.instances_available || (!next.identity_available && self.identity_available));
        let (cost_snapshot, retain_costs) =
            self.cost_snapshot.merge_refresh(next.cost_snapshot.clone());
        if retain_identity {
            next.metadata.account.clone_from(&self.metadata.account);
            next.metadata.principal.clone_from(&self.metadata.principal);
            next.identity_available = true;
        }
        if retain_inventory {
            next.storage = self.storage.clone();
            next.metadata.regions.clone_from(&self.metadata.regions);
            preserve_overview_row(self, &mut next, |row| {
                row.action == AwsAction::Section(AwsSection::Storage)
            });
            next.inventory_available = true;
        }
        if retain_instances {
            next.instances_available = self.instances_available;
            next.instances_complete = false;
            next.app_hosts = self.app_hosts.clone();
            next.builders = self.builders.clone();
            next.hosts = self.hosts.clone();
            next.findings = self.findings.clone();
            for section in [
                AwsSection::AppHosts,
                AwsSection::Builders,
                AwsSection::Findings,
            ] {
                preserve_overview_row(self, &mut next, |row| {
                    row.action == AwsAction::Section(section)
                });
            }
        }
        reconcile::replace_costs(&mut next, cost_snapshot, retain_costs);
        if retain_identity || retain_inventory || retain_instances || retain_costs.any() {
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

fn resource_summary(
    kind: crate::model::ResourceKind,
    id: Uuid,
    label: String,
    context: String,
) -> ResourceSummary {
    ResourceSummary {
        kind,
        id,
        label,
        context: Some(context),
    }
}

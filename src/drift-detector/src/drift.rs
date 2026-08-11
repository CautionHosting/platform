// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core drift detection logic.
//!
//! This module provides the main functionality for comparing expected state
//! (from database) with actual state (from AWS) and reporting differences.

use crate::aws::Ec2Instance;
use crate::db::{ComputeResource, OrgUser, ProviderAccount, ResourceState};
use aws_sdk_ec2::types::InstanceStateName;
use std::collections::{HashMap, HashSet};

/// Tag key marking the entity that created an EC2 instance.
const MANAGED_BY_TAG: &str = "ManagedBy";
/// Value of [`MANAGED_BY_TAG`] on build runner instances.
const MANAGED_BY_BUILDER: &str = "caution-builder";
/// Value of [`MANAGED_BY_TAG`] applied by the deployment Terraform/OpenTofu
/// provider `default_tags` block to every provisioned resource.
const MANAGED_BY_TOFU: &str = "caution+tofu";
/// Tag key on build runner instances holding the build UUID.
const BUILD_ID_TAG: &str = "BuildId";
/// Tag key used by AWS for the instance display name.
const NAME_TAG: &str = "Name";
/// Tag key on deployment resources holding the database resource UUID.
const RESOURCE_ID_TAG: &str = "ResourceId";
/// Tag key on managed on-prem deployment resources holding the deployment ID.
const DEPLOYMENT_ID_TAG: &str = "caution:deployment-id";
/// Tag key on deployment instances holding the configured HTTP domain.
const CONFIG_DOMAIN_TAG: &str = "ConfigDomain";
/// Tag key on instances holding the UUID of the organization they were
/// launched for. Both build runners and deployments are tagged with their
/// owning organization, so a fully-managed AWS account shared across
/// organizations can attribute each instance to its owner.
const ORG_ID_TAG: &str = "org_id";
/// Legacy tag key recognized for backward compatibility. The platform now
/// tags deployments with [`RESOURCE_ID_TAG`]; this alias was never emitted by
/// the current codebase but is accepted so older orphaned instances are still
/// flagged.
const LEGACY_RESOURCE_ID_TAG: &str = "caution:resource_id";
/// Prefix of the `Name` tag on build runner instances.
const BUILDER_NAME_PREFIX: &str = "caution-builder-";

/// Represents a type of drift detected between expected and actual state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftType {
    /// Resource exists in database but not in AWS.
    MissingInAws(String),

    /// Resource exists in AWS but not in database.
    OrphanedInAws(String),

    /// Resource state differs (expected vs actual).
    StateMismatch {
        /// The affected resource's provider-side identifier.
        resource_id: String,
        /// The state recorded in the database.
        expected: String,
        /// The state reported by AWS.
        actual: String,
    },

    /// Public IP address differs from expected.
    IpMismatch {
        /// The affected resource's provider-side identifier.
        resource_id: String,
        /// The IP address recorded in the database.
        expected: Option<String>,
        /// The IP address reported by AWS.
        actual: Option<String>,
    },

    /// Instance type differs from configuration.
    InstanceTypeMismatch {
        /// The affected resource's provider-side identifier.
        resource_id: String,
        /// The instance type recorded in the configuration.
        expected: Option<String>,
        /// The instance type reported by AWS.
        actual: Option<String>,
    },
}

/// A detected drift between expected and actual state.
#[derive(Debug, Clone)]
pub struct DriftReport {
    /// The type of drift detected.
    pub drift_type: DriftType,

    /// Human-readable description of the drift.
    pub description: String,

    /// Severity level of this drift.
    pub severity: DriftSeverity,
}

/// Severity level of a drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    /// Informational - no immediate action required.
    Info,

    /// Warning - should be reviewed soon.
    Warning,

    /// Critical - requires immediate attention.
    Critical,
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftSeverity::Info => write!(f, "INFO"),
            DriftSeverity::Warning => write!(f, "WARNING"),
            DriftSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Error returned when a drift severity string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid drift severity `{0}` (expected `info`, `warning`, or `critical`)")]
pub struct ParseDriftSeverityError(String);

impl std::str::FromStr for DriftSeverity {
    type Err = ParseDriftSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(Self::Info),
            "warning" | "warn" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            other => Err(ParseDriftSeverityError(other.to_string())),
        }
    }
}

impl std::fmt::Display for DriftType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftType::MissingInAws(id) => write!(f, "resource {id} missing in AWS"),
            DriftType::OrphanedInAws(id) => write!(f, "untracked resource {id} in AWS"),
            DriftType::StateMismatch {
                resource_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "resource {resource_id}: state mismatch (expected: {expected}, actual: {actual})"
                )
            }
            DriftType::IpMismatch {
                resource_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "resource {resource_id}: IP mismatch (expected: {expected:?}, actual: {actual:?})"
                )
            }
            DriftType::InstanceTypeMismatch {
                resource_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "resource {resource_id}: instance type mismatch (expected: {expected:?}, actual: {actual:?})"
                )
            }
        }
    }
}

impl DriftReport {
    /// Create a new drift report.
    #[must_use]
    pub fn new(drift_type: DriftType, description: String, severity: DriftSeverity) -> Self {
        Self {
            drift_type,
            description,
            severity,
        }
    }

    /// Get the resource ID from this drift (if applicable).
    #[must_use]
    pub fn resource_id(&self) -> Option<&str> {
        match &self.drift_type {
            DriftType::MissingInAws(id) | DriftType::OrphanedInAws(id) => Some(id),
            DriftType::StateMismatch { resource_id, .. }
            | DriftType::IpMismatch { resource_id, .. }
            | DriftType::InstanceTypeMismatch { resource_id, .. } => Some(resource_id),
        }
    }
}

impl std::fmt::Display for DriftReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.severity, self.drift_type)?;
        if !self.description.is_empty() {
            write!(f, ": {}", self.description)?;
        }
        Ok(())
    }
}

/// A complete drift detection report for an organization.
#[derive(Debug, Clone)]
pub struct OrganizationDriftReport {
    /// The organization ID this report is for.
    pub org_id: uuid::Uuid,

    /// The provider accounts that were scanned for this organization.
    pub accounts: Vec<ProviderAccount>,

    /// The users belonging to this organization.
    pub users: Vec<OrgUser>,

    /// All detected drifts.
    pub drifts: Vec<DriftReport>,

    /// Summary counts.
    pub summary: DriftSummary,
}

impl OrganizationDriftReport {
    /// Create a new organization drift report from the scanned accounts, the
    /// organization's users, and the drifts detected across the accounts.
    #[must_use]
    pub fn new(
        org_id: uuid::Uuid,
        accounts: Vec<ProviderAccount>,
        users: Vec<OrgUser>,
        drifts: Vec<DriftReport>,
    ) -> Self {
        let mut summary = DriftSummary::default();

        for drift in &drifts {
            match &drift.drift_type {
                DriftType::MissingInAws(_) => summary.missing_in_aws += 1,
                DriftType::OrphanedInAws(_) => summary.orphaned_in_aws += 1,
                DriftType::StateMismatch { .. } => summary.state_mismatches += 1,
                DriftType::IpMismatch { .. } => summary.ip_mismatches += 1,
                DriftType::InstanceTypeMismatch { .. } => summary.instance_type_mismatches += 1,
            }
        }

        Self {
            org_id,
            accounts,
            users,
            drifts,
            summary,
        }
    }

    /// Keep only drifts at or above `min_severity`, recomputing the summary.
    ///
    /// Account and user information is preserved.
    #[must_use]
    pub fn with_severity(self, min_severity: DriftSeverity) -> Self {
        let filtered_drifts = self
            .drifts
            .into_iter()
            .filter(|d| d.severity >= min_severity)
            .collect();

        OrganizationDriftReport::new(self.org_id, self.accounts, self.users, filtered_drifts)
    }

    /// Check if there are any critical drifts.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.drifts
            .iter()
            .any(|d| d.severity == DriftSeverity::Critical)
    }
}

/// Summary of drift counts by type.
#[derive(Debug, Clone, Default)]
pub struct DriftSummary {
    /// Resources in DB but not in AWS.
    pub missing_in_aws: u32,

    /// Resources in AWS but not in DB.
    pub orphaned_in_aws: u32,

    /// State mismatches.
    pub state_mismatches: u32,

    /// IP address mismatches.
    pub ip_mismatches: u32,

    /// Instance type mismatches.
    pub instance_type_mismatches: u32,
}

impl std::fmt::Display for DriftSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Drift Summary: ")?;
        let mut parts = Vec::new();

        if self.missing_in_aws > 0 {
            parts.push(format!("{} missing in AWS", self.missing_in_aws));
        }
        if self.orphaned_in_aws > 0 {
            parts.push(format!("{} orphaned in AWS", self.orphaned_in_aws));
        }
        if self.state_mismatches > 0 {
            parts.push(format!("{} state mismatches", self.state_mismatches));
        }
        if self.ip_mismatches > 0 {
            parts.push(format!("{} IP mismatches", self.ip_mismatches));
        }
        if self.instance_type_mismatches > 0 {
            parts.push(format!(
                "{} instance type mismatches",
                self.instance_type_mismatches
            ));
        }

        if parts.is_empty() {
            write!(f, "No drift detected")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

/// Detect drift for a single resource against its actual AWS state.
///
/// When the resource is missing in AWS the severity depends on the expected
/// state: critical when the resource should be running, warning when it should
/// be stopped or failed, and informational while it is still being
/// provisioned. Resources expected to be terminated are not reported as
/// missing, since a missing instance is consistent with a terminated one.
/// State and instance-type differences are warnings; public IP differences
/// are informational.
#[must_use]
pub fn detect_resource_drift(
    expected: &ComputeResource,
    actual: Option<&Ec2Instance>,
) -> Vec<DriftReport> {
    let mut drifts = Vec::new();
    let resource_name = expected.resource_name.as_deref().unwrap_or("unknown");
    let region = expected.region.as_deref().unwrap_or("unknown");

    match actual {
        None => {
            if expected.state != ResourceState::Terminated {
                let severity = match expected.state {
                    ResourceState::Running => DriftSeverity::Critical,
                    ResourceState::Stopped | ResourceState::Failed => DriftSeverity::Warning,
                    ResourceState::Initialized
                    | ResourceState::Pending
                    | ResourceState::Terminated => DriftSeverity::Info,
                };

                let expected_instance_type = expected
                    .configuration
                    .as_ref()
                    .and_then(|config| config.get("instance_type"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("not configured");

                drifts.push(DriftReport::new(
                    DriftType::MissingInAws(expected.provider_resource_id.clone()),
                    format!(
                        "Resource '{}' (state: {}, region: {}) exists in database but not found in AWS; \
                         expected public IP: {:?}, expected instance type: {}",
                        resource_name,
                        expected.state.as_str(),
                        region,
                        expected.public_ip,
                        expected_instance_type,
                    ),
                    severity,
                ));
            }
        }
        Some(instance) => {
            let actual_state = db_state_from_aws(&instance.state);
            if actual_state != expected.state {
                drifts.push(DriftReport::new(
                    DriftType::StateMismatch {
                        resource_id: expected.provider_resource_id.clone(),
                        expected: expected.state.as_str().to_string(),
                        actual: actual_state.as_str().to_string(),
                    },
                    format!(
                        "Resource '{}' (region: {}) state differs: DB says {}, AWS says {}",
                        resource_name,
                        region,
                        expected.state.as_str(),
                        actual_state.as_str(),
                    ),
                    DriftSeverity::Warning,
                ));
            }

            if instance.public_ip.as_deref() != expected.public_ip.as_deref() {
                drifts.push(DriftReport::new(
                    DriftType::IpMismatch {
                        resource_id: expected.provider_resource_id.clone(),
                        expected: expected.public_ip.clone(),
                        actual: instance.public_ip.clone(),
                    },
                    format!(
                        "Resource '{}' (region: {}) IP differs: DB has {:?}, AWS has {:?}",
                        resource_name, region, expected.public_ip, instance.public_ip
                    ),
                    DriftSeverity::Info,
                ));
            }

            if let Some(config) = &expected.configuration
                && let Some(instance_type) = config.get("instance_type").and_then(|v| v.as_str())
            {
                let actual_type = instance.instance_type.as_deref();
                if Some(instance_type) != actual_type {
                    drifts.push(DriftReport::new(
                        DriftType::InstanceTypeMismatch {
                            resource_id: expected.provider_resource_id.clone(),
                            expected: Some(instance_type.to_string()),
                            actual: instance.instance_type.clone(),
                        },
                        format!(
                            "Resource '{}' (region: {}) instance type differs: DB config says {}, AWS has {:?}",
                            resource_name, region, instance_type, instance.instance_type
                        ),
                        DriftSeverity::Warning,
                    ));
                }
            }
        }
    }

    drifts
}

/// The kind of Caution-managed resource an EC2 instance belongs to, inferred
/// from its tags.
///
/// This mirrors how the platform categorizes the instances it launches:
/// ephemeral build runners (tagged `ManagedBy: caution-builder`) and deployed
/// enclaves (provisioned via Terraform/OpenTofu with `ManagedBy:
/// caution+tofu` as a provider default tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CautionResourceKind {
    /// An ephemeral enclave build runner instance.
    Builder,
    /// A deployed enclave instance.
    Deployment,
}

impl std::fmt::Display for CautionResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CautionResourceKind::Builder => write!(f, "builder"),
            CautionResourceKind::Deployment => write!(f, "deployment"),
        }
    }
}

/// Classify an EC2 instance by its tags as the kind of Caution-managed
/// resource it is, or `None` when it is not managed by Caution.
///
/// Builders are recognized by `ManagedBy: caution-builder`, the `BuildId`
/// tag, or the `caution-builder-` `Name` prefix. Deployments are recognized
/// by the `ResourceId`, `caution:deployment-id`, or `ConfigDomain` tags
/// emitted by the deployment templates, by the `ManagedBy: caution+tofu`
/// provider default tag, or by the legacy `caution:resource_id` alias.
/// Builder markers take precedence so a managed on-prem builder (which also
/// carries `caution:deployment-id`) is still categorized as a builder.
#[must_use]
pub fn classify_caution_resource(tags: &HashMap<String, String>) -> Option<CautionResourceKind> {
    if is_builder(tags) {
        Some(CautionResourceKind::Builder)
    } else if is_deployment(tags) {
        Some(CautionResourceKind::Deployment)
    } else {
        None
    }
}

fn is_builder(tags: &HashMap<String, String>) -> bool {
    tags.get(MANAGED_BY_TAG)
        .is_some_and(|value| value == MANAGED_BY_BUILDER)
        || tags.contains_key(BUILD_ID_TAG)
        || tags
            .get(NAME_TAG)
            .is_some_and(|value| value.starts_with(BUILDER_NAME_PREFIX))
}

fn is_deployment(tags: &HashMap<String, String>) -> bool {
    tags.contains_key(RESOURCE_ID_TAG)
        || tags.contains_key(DEPLOYMENT_ID_TAG)
        || tags.contains_key(CONFIG_DOMAIN_TAG)
        || tags.contains_key(LEGACY_RESOURCE_ID_TAG)
        || tags
            .get(MANAGED_BY_TAG)
            .is_some_and(|value| value == MANAGED_BY_TOFU)
}

/// Detect orphaned resources: EC2 instances that exist in AWS but are not
/// tracked in the database.
///
/// Untracked instances that match the platform's tagging scheme (see
/// [`classify_caution_resource`]) are treated as Caution-managed resources
/// and reported as critical; all other untracked instances are reported as
/// informational. The owning provider account is included in the report
/// description, along with the full tag set (keys and values).
///
/// Orphan reports are scoped to the organization owning `account`. Fully
/// managed deployments share one AWS account across all organizations, so
/// every organization's scan lists every other organization's instances;
/// without scoping each run would report all of them N times. An instance is
/// in scope when its `org_id` tag names the account's organization, or when
/// its `ResourceId` tag resolves to a database resource of that organization.
/// Instances that cannot be attributed to any organization are reported once
/// by [`detect_unattributed_orphaned_resources`] after all organizations have
/// been scanned.
///
/// Instances carrying a `ResourceId` tag are cross-referenced against
/// `db_resources`: the tag value is the database resource UUID, so the report
/// names the matching resource and its expected state when the row still
/// exists, and notes when it does not. An instance is only considered tracked
/// when its instance ID is recorded for the same provider account; the
/// resource lookup itself is organization-wide.
#[must_use]
pub fn detect_orphaned_resources(
    db_resources: &[ComputeResource],
    aws_instances: &[Ec2Instance],
    account: &ProviderAccount,
) -> Vec<DriftReport> {
    let db_resource_ids: HashSet<String> = db_resources
        .iter()
        .filter(|resource| resource.provider_account_id == account.id)
        .map(|resource| resource.provider_resource_id.clone())
        .collect();

    let mut orphaned = Vec::new();

    for instance in aws_instances {
        if !db_resource_ids.contains(&instance.instance_id)
            && instance_belongs_to_org(instance, account.organization_id, db_resources)
        {
            let kind = classify_caution_resource(&instance.tags);

            let severity = if kind.is_some() {
                DriftSeverity::Critical
            } else {
                DriftSeverity::Info
            };

            orphaned.push(DriftReport::new(
                DriftType::OrphanedInAws(instance.instance_id.clone()),
                format!(
                    "Instance '{}' exists in AWS but not tracked in database \
                     (account: {}, region: {}): state {:?}, type: {:?}, \
                     public IP: {:?}, private IP: {:?}, VPC: {:?}, subnet: {:?}, \
                     tags: {}{}{}",
                    instance.instance_id,
                    account.external_account_id,
                    account.region,
                    instance.state,
                    instance.instance_type,
                    instance.public_ip,
                    instance.private_ip,
                    instance.vpc_id,
                    instance.subnet_id,
                    format_tags(&instance.tags),
                    kind.map(|kind| format!(" (appears to be a Caution {kind})"))
                        .unwrap_or_default(),
                    describe_db_match(instance, db_resources),
                ),
                severity,
            ));
        }
    }

    orphaned
}

/// Whether an instance can be attributed to the given organization: its
/// `org_id` tag names the organization, or its `ResourceId` tag resolves to a
/// database resource owned by the organization.
fn instance_belongs_to_org(
    instance: &Ec2Instance,
    org_id: uuid::Uuid,
    db_resources: &[ComputeResource],
) -> bool {
    if instance
        .tags
        .get(ORG_ID_TAG)
        .is_some_and(|value| value == &org_id.to_string())
    {
        return true;
    }

    tagged_resource(instance, db_resources)
        .is_some_and(|resource| resource.organization_id == org_id)
}

/// Format a tag map as `key=value` pairs sorted by key, e.g.
/// `{ManagedBy=caution+tofu, Name=i-456, ResourceId=…}`.
fn format_tags(tags: &HashMap<String, String>) -> String {
    let mut pairs: Vec<(&str, &str)> = tags
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    pairs.sort_unstable();

    if pairs.is_empty() {
        "{}".to_string()
    } else {
        format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// The expected instance type recorded in a resource's configuration, when
/// present.
fn expected_instance_type(resource: &ComputeResource) -> &str {
    resource
        .configuration
        .as_ref()
        .and_then(|config| config.get("instance_type"))
        .and_then(|value| value.as_str())
        .unwrap_or("not configured")
}

/// The value of an instance's resource-id tag (`ResourceId`, or its legacy
/// `caution:resource_id` alias), when present.
fn tagged_resource_id(instance: &Ec2Instance) -> Option<&str> {
    instance
        .tags
        .get(RESOURCE_ID_TAG)
        .or_else(|| instance.tags.get(LEGACY_RESOURCE_ID_TAG))
        .map(String::as_str)
}

/// Look up the database resource referenced by an instance's resource-id tag.
///
/// The `ResourceId` tag (or its legacy alias) holds the database resource
/// UUID. Builders do not carry one, so this returns `None` for them.
fn tagged_resource<'a>(
    instance: &Ec2Instance,
    db_resources: &'a [ComputeResource],
) -> Option<&'a ComputeResource> {
    let resource_id = tagged_resource_id(instance)?;
    uuid::Uuid::parse_str(resource_id)
        .ok()
        .and_then(|resource_uuid| {
            db_resources
                .iter()
                .find(|resource| resource.id == resource_uuid)
        })
}

/// Build the database-match clause for an orphaned instance's description.
///
/// When the resource-id tag is absent no clause is emitted. When it is
/// present, the report names the matching resource and its expected state, or
/// notes that no row matches.
fn describe_db_match(instance: &Ec2Instance, db_resources: &[ComputeResource]) -> String {
    let Some(resource_id) = tagged_resource_id(instance) else {
        return String::new();
    };

    match tagged_resource(instance, db_resources) {
        Some(resource) => format!(
            "; matching database resource '{}' (expected state: {}, region: {}, \
             public IP: {:?}, instance type: {})",
            resource.resource_name.as_deref().unwrap_or("unknown"),
            resource.state.as_str(),
            resource.region.as_deref().unwrap_or("unknown"),
            resource.public_ip,
            expected_instance_type(resource),
        ),
        None => {
            format!("; no matching database resource for tagged resource id '{resource_id}'")
        }
    }
}

/// An EC2 instance observed while scanning a provider account, together with
/// the account it was listed through.
///
/// Instances in a shared fully-managed account are listed once per
/// organization that scans it; [`detect_unattributed_orphaned_resources`]
/// deduplicates them by instance ID.
#[derive(Debug, Clone)]
pub struct ScannedInstance {
    /// The provider account the instance was listed through.
    pub account: ProviderAccount,
    /// The instance itself.
    pub instance: Ec2Instance,
}

/// Detect orphaned instances that could not be attributed to any
/// organization.
///
/// Runs after every organization has been scanned. An instance is attributed
/// to an organization when its `org_id` tag names one of `known_org_ids`, or
/// when its `ResourceId` tag resolves to a database resource owned by one of
/// those organizations. Instances tracked in `db_resources` by instance ID
/// are skipped, and duplicate sightings of the same instance are reported
/// once (a shared account is listed once per organization). Everything else
/// is reported here so that no dangling instance in a shared account silently
/// escapes the per-organization passes.
///
/// Severity follows the same rule as [`detect_orphaned_resources`]: instances
/// matching the platform's tagging scheme are critical, everything else is
/// informational.
#[must_use]
pub fn detect_unattributed_orphaned_resources(
    db_resources: &[ComputeResource],
    scanned_instances: &[ScannedInstance],
    known_org_ids: &[uuid::Uuid],
) -> Vec<DriftReport> {
    let known_orgs: HashSet<&uuid::Uuid> = known_org_ids.iter().collect();
    let tracked_ids: HashSet<&str> = db_resources
        .iter()
        .map(|resource| resource.provider_resource_id.as_str())
        .collect();

    let mut seen: HashSet<&str> = HashSet::new();
    let mut unattributed = Vec::new();

    for scanned in scanned_instances {
        let instance = &scanned.instance;

        if tracked_ids.contains(instance.instance_id.as_str()) {
            continue;
        }
        if !seen.insert(instance.instance_id.as_str()) {
            continue;
        }
        if instance_attributed_to_known_org(instance, db_resources, &known_orgs) {
            continue;
        }

        let kind = classify_caution_resource(&instance.tags);
        let severity = if kind.is_some() {
            DriftSeverity::Critical
        } else {
            DriftSeverity::Info
        };

        unattributed.push(DriftReport::new(
            DriftType::OrphanedInAws(instance.instance_id.clone()),
            format!(
                "Instance '{}' exists in AWS but could not be attributed to any organization \
                 (account: {}, region: {}): state {:?}, type: {:?}, \
                 public IP: {:?}, private IP: {:?}, VPC: {:?}, subnet: {:?}, \
                 tags: {}{}{}",
                instance.instance_id,
                scanned.account.external_account_id,
                scanned.account.region,
                instance.state,
                instance.instance_type,
                instance.public_ip,
                instance.private_ip,
                instance.vpc_id,
                instance.subnet_id,
                format_tags(&instance.tags),
                kind.map(|kind| format!(" (appears to be a Caution {kind})"))
                    .unwrap_or_default(),
                describe_db_match(instance, db_resources),
            ),
            severity,
        ));
    }

    unattributed
}

/// Whether an instance can be attributed to one of the known organizations:
/// its `org_id` tag names a known organization, or its `ResourceId` tag
/// resolves to a database resource owned by a known organization.
fn instance_attributed_to_known_org(
    instance: &Ec2Instance,
    db_resources: &[ComputeResource],
    known_orgs: &HashSet<&uuid::Uuid>,
) -> bool {
    let org_tagged = instance
        .tags
        .get(ORG_ID_TAG)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .is_some_and(|org_id| known_orgs.contains(&org_id));

    org_tagged
        || tagged_resource(instance, db_resources)
            .is_some_and(|resource| known_orgs.contains(&resource.organization_id))
}

/// Convert AWS instance state to database resource state.
///
/// Transitional states (`stopping`, `shutting-down`) map to `Stopped` since
/// the database has no transitional lifecycle states. `Unknown` maps to
/// `Failed` so an unparseable state surfaces as drift rather than being
/// silently treated as a real state.
fn db_state_from_aws(state: &InstanceStateName) -> ResourceState {
    match state {
        InstanceStateName::Pending => ResourceState::Pending,
        InstanceStateName::Running => ResourceState::Running,
        InstanceStateName::ShuttingDown
        | InstanceStateName::Stopping
        | InstanceStateName::Stopped => ResourceState::Stopped,
        InstanceStateName::Terminated => ResourceState::Terminated,
        _ => ResourceState::Failed,
    }
}

/// Format an organization's users as a display section, one per line:
/// `- username (email)` when an email is on file, `- username` otherwise.
///
/// Returns an empty string when there are no users, so the section can be
/// omitted from reports and messages.
#[must_use]
pub fn format_org_users(users: &[OrgUser]) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();

    if !users.is_empty() {
        output.push_str("Users:\n");
        for user in users {
            match &user.email {
                Some(email) => {
                    writeln!(output, "  - {} ({})", user.username, email)
                        .expect("writing to a String cannot fail");
                }
                None => {
                    writeln!(output, "  - {}", user.username)
                        .expect("writing to a String cannot fail");
                }
            }
        }
    }

    output
}

/// Format drift reports for display.
///
/// The report lists the scanned provider accounts, the organization's users,
/// the drift summary, and each drift ordered by resource ID.
#[must_use]
pub fn format_drift_report(report: &OrganizationDriftReport) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();

    writeln!(output, "Organization {} Drift Report", report.org_id)
        .expect("writing to a String cannot fail");

    if !report.accounts.is_empty() {
        output.push_str("Provider accounts:\n");
        for account in &report.accounts {
            writeln!(
                output,
                "  - {} (region: {}, role: {})",
                account.external_account_id,
                account.region,
                account.role_arn.as_deref().unwrap_or("none"),
            )
            .expect("writing to a String cannot fail");
        }
    }

    output.push_str(&format_org_users(&report.users));

    writeln!(output, "{}", report.summary).expect("writing to a String cannot fail");
    output.push('\n');

    if report.drifts.is_empty() {
        output.push_str("No drift detected.\n");
    } else {
        let mut drifts: Vec<&DriftReport> = report.drifts.iter().collect();
        drifts.sort_by_key(|drift| drift.resource_id());
        for (i, drift) in drifts.iter().enumerate() {
            writeln!(output, "{}. {drift}", i + 1).expect("writing to a String cannot fail");
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_resource(id: &str, state: ResourceState) -> ComputeResource {
        ComputeResource {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            provider_account_id: uuid::Uuid::new_v4(),
            provider_resource_id: id.to_string(),
            resource_name: Some(format!("test-{}", id)),
            state,
            region: Some("us-west-2".to_string()),
            public_ip: None,
            configuration: None,
        }
    }

    #[test]
    fn test_detect_missing_resource() {
        let expected = create_test_resource("i-123", ResourceState::Running);

        let drifts = detect_resource_drift(&expected, None);

        assert_eq!(drifts.len(), 1);
        match &drifts[0].drift_type {
            DriftType::MissingInAws(id) => assert_eq!(id, "i-123"),
            _ => panic!("Expected MissingInAws drift type"),
        }
        assert_eq!(drifts[0].severity, DriftSeverity::Critical);
    }

    #[test]
    fn test_detect_state_mismatch() {
        let expected = create_test_resource("i-123", ResourceState::Running);

        let actual = Ec2Instance {
            instance_id: "i-123".to_string(),
            instance_type: Some("c5.xlarge".to_string()),
            state: InstanceStateName::Stopped,
            public_ip: None,
            private_ip: None,
            vpc_id: None,
            subnet_id: None,
            tags: HashMap::new(),
        };

        let drifts = detect_resource_drift(&expected, Some(&actual));

        assert_eq!(drifts.len(), 1);
        match &drifts[0].drift_type {
            DriftType::StateMismatch {
                resource_id,
                expected: exp_state,
                actual: act_state,
            } => {
                assert_eq!(resource_id, "i-123");
                assert_eq!(exp_state, "running");
                assert_eq!(act_state, "stopped");
            }
            _ => panic!("Expected StateMismatch drift type"),
        }
    }

    #[test]
    fn test_detect_orphaned_resource() {
        let account = test_account();
        let db_resources = vec![tracked_resource(&account, "i-123", ResourceState::Running)];

        let aws_instances = vec![
            tagged_instance("i-123", HashMap::new()),
            ensure_org_tag(
                Ec2Instance {
                    instance_id: "i-456".to_string(),
                    instance_type: Some("t3.micro".to_string()),
                    state: InstanceStateName::Running,
                    public_ip: Some("54.123.45.67".to_string()),
                    private_ip: Some("10.0.1.100".to_string()),
                    vpc_id: Some("vpc-12345678".to_string()),
                    subnet_id: Some("subnet-12345678".to_string()),
                    tags: HashMap::new(),
                },
                account.organization_id,
            ),
        ];

        let orphaned = detect_orphaned_resources(&db_resources, &aws_instances, &account);

        assert_eq!(orphaned.len(), 1);
        match &orphaned[0].drift_type {
            DriftType::OrphanedInAws(id) => assert_eq!(id, "i-456"),
            _ => panic!("Expected OrphanedInAws drift type"),
        }
        assert!(orphaned[0].description.contains("123456789012"));
        assert!(orphaned[0].description.contains("t3.micro"));
        assert!(orphaned[0].description.contains("54.123.45.67"));
    }

    fn test_account() -> ProviderAccount {
        ProviderAccount {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            external_account_id: "123456789012".to_string(),
            role_arn: None,
            region: "us-west-2".to_string(),
        }
    }

    /// A resource tracked in the database for the given provider account.
    fn tracked_resource(
        account: &ProviderAccount,
        instance_id: &str,
        state: ResourceState,
    ) -> ComputeResource {
        ComputeResource {
            id: uuid::Uuid::new_v4(),
            organization_id: account.organization_id,
            provider_account_id: account.id,
            provider_resource_id: instance_id.to_string(),
            resource_name: Some(format!("app-{}", &instance_id[2..])),
            state,
            region: Some("us-west-2".to_string()),
            public_ip: None,
            configuration: Some(serde_json::json!({ "instance_type": "c5.xlarge" })),
        }
    }

    /// A resource with a known database ID and the given account's
    /// organization, so the `ResourceId` tag lookup can match it within that
    /// account's scan.
    fn tagged_resource(
        account: &ProviderAccount,
        resource_uuid: uuid::Uuid,
        instance_id: &str,
        state: ResourceState,
    ) -> ComputeResource {
        ComputeResource {
            id: resource_uuid,
            organization_id: account.organization_id,
            provider_account_id: account.id,
            provider_resource_id: instance_id.to_string(),
            resource_name: Some("app-matching".to_string()),
            state,
            region: Some("us-west-2".to_string()),
            public_ip: Some("1.2.3.4".to_string()),
            configuration: Some(serde_json::json!({ "instance_type": "c5.xlarge" })),
        }
    }

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn tagged_instance(instance_id: &str, tags: HashMap<String, String>) -> Ec2Instance {
        Ec2Instance {
            instance_id: instance_id.to_string(),
            instance_type: None,
            state: InstanceStateName::Running,
            public_ip: None,
            private_ip: None,
            vpc_id: None,
            subnet_id: None,
            tags,
        }
    }

    /// Tag an instance with the given organization unless it already carries
    /// an `org_id` tag.
    fn ensure_org_tag(mut instance: Ec2Instance, org_id: uuid::Uuid) -> Ec2Instance {
        instance
            .tags
            .entry(ORG_ID_TAG.to_string())
            .or_insert_with(|| org_id.to_string());
        instance
    }

    fn orphaned_from(db_resources: &[ComputeResource], instance: Ec2Instance) -> DriftReport {
        let account = test_account();
        let instance = ensure_org_tag(instance, account.organization_id);
        let orphaned = detect_orphaned_resources(db_resources, &[instance], &account);
        assert_eq!(orphaned.len(), 1, "expected exactly one orphan report");
        orphaned.into_iter().next().expect("one orphan reported")
    }

    #[test]
    fn test_orphaned_resource_id_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance(
                "i-456",
                tags(&[("ResourceId", "550e8400-e29b-41d4-a716-446655440000")]),
            ),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_managed_by_tofu_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ManagedBy", "caution+tofu")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_config_domain_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ConfigDomain", "app.example.com")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_legacy_resource_id_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("caution:resource_id", "cr-123")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_org_tagged_non_caution_instance_is_info() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(&db_resources, tagged_instance("i-456", HashMap::new()));

        assert_eq!(report.severity, DriftSeverity::Info);
        assert!(!report.description.contains("appears to be a Caution"));
    }

    #[test]
    fn test_orphaned_managed_by_value_must_be_caution_builder() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];

        let foreign = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ManagedBy", "CloudFormation")])),
        );
        assert_eq!(foreign.severity, DriftSeverity::Info);
        assert!(!foreign.description.contains("appears to be a Caution"));

        let builder = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ManagedBy", "caution-builder")])),
        );
        assert_eq!(builder.severity, DriftSeverity::Critical);
        assert!(builder.description.contains("Caution builder"));
    }

    #[test]
    fn test_orphaned_builder_build_id_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("BuildId", "b-123")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution builder"));
    }

    #[test]
    fn test_orphaned_builder_name_prefixed_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("Name", "caution-builder-abc12345")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution builder"));
    }

    #[test]
    fn test_orphaned_onprem_builder_is_reported_as_builder_not_deployment() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance(
                "i-456",
                tags(&[
                    ("ManagedBy", "caution-builder"),
                    ("caution:deployment-id", "dep-1"),
                ]),
            ),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution builder"));
        assert!(!report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_deployment_id_tagged_instance_is_critical() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance(
                "i-456",
                tags(&[("caution:deployment-id", &uuid::Uuid::new_v4().to_string())]),
            ),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_description_includes_full_tag_values() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance(
                "i-456",
                tags(&[
                    ("ResourceId", "550e8400-e29b-41d4-a716-446655440000"),
                    ("Name", "i-456"),
                    ("ManagedBy", "caution+tofu"),
                    ("ConfigDomain", "app.example.com"),
                ]),
            ),
        );

        assert!(
            report
                .description
                .contains("ResourceId=550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(report.description.contains("ManagedBy=caution+tofu"));
        assert!(report.description.contains("ConfigDomain=app.example.com"));
        assert!(report.description.contains("Name=i-456"));
    }

    #[test]
    fn test_orphaned_matches_database_resource_and_expected_state() {
        let account = test_account();
        let resource_uuid = uuid::Uuid::new_v4();
        let db_resources = vec![
            create_test_resource("i-123", ResourceState::Running),
            tagged_resource(&account, resource_uuid, "i-999", ResourceState::Running),
        ];
        let orphaned = detect_orphaned_resources(
            &db_resources,
            &[tagged_instance(
                "i-456",
                tags(&[("ResourceId", &resource_uuid.to_string())]),
            )],
            &account,
        );
        assert_eq!(orphaned.len(), 1);
        let report = &orphaned[0];

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(
            report
                .description
                .contains("matching database resource 'app-matching'")
        );
        assert!(report.description.contains("expected state: running"));
        assert!(report.description.contains("region: us-west-2"));
        assert!(report.description.contains("public IP: Some(\"1.2.3.4\")"));
        assert!(report.description.contains("instance type: c5.xlarge"));
    }

    #[test]
    fn test_orphaned_resource_id_without_db_match_notes_missing_row() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance(
                "i-456",
                tags(&[("ResourceId", "550e8400-e29b-41d4-a716-446655440000")]),
            ),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(
            report
                .description
                .contains("no matching database resource for tagged resource id '550e8400")
        );
    }

    #[test]
    fn test_orphaned_matches_stopped_database_resource_state() {
        let account = test_account();
        let resource_uuid = uuid::Uuid::new_v4();
        let db_resources = vec![
            create_test_resource("i-123", ResourceState::Running),
            tagged_resource(&account, resource_uuid, "i-999", ResourceState::Stopped),
        ];
        let orphaned = detect_orphaned_resources(
            &db_resources,
            &[tagged_instance(
                "i-456",
                tags(&[("ResourceId", &resource_uuid.to_string())]),
            )],
            &account,
        );
        assert_eq!(orphaned.len(), 1);
        assert!(orphaned[0].description.contains("expected state: stopped"));
    }

    #[test]
    fn test_orphaned_builder_has_no_db_match_clause() {
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ManagedBy", "caution-builder")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution builder"));
        assert!(!report.description.contains("matching database resource"));
        assert!(!report.description.contains("no matching database resource"));
    }

    #[test]
    fn test_orphaned_other_orgs_instance_not_reported_in_this_orgs_scan() {
        let account = test_account();
        let db_resources = vec![tracked_resource(&account, "i-123", ResourceState::Running)];

        let other_orgs_instance = tagged_instance(
            "i-456",
            tags(&[
                ("org_id", "550e8400-e29b-41d4-a716-446655440000"),
                ("ManagedBy", "caution+tofu"),
            ]),
        );

        let orphaned = detect_orphaned_resources(&db_resources, &[other_orgs_instance], &account);
        assert!(
            orphaned.is_empty(),
            "another org's instance must not be reported here"
        );
    }

    #[test]
    fn test_unattributed_untagged_instance_reported_once_across_accounts() {
        let account_a = test_account();
        let account_b = test_account();
        let instance = tagged_instance("i-456", HashMap::new());
        let scanned = vec![
            ScannedInstance {
                account: account_a.clone(),
                instance: instance.clone(),
            },
            ScannedInstance {
                account: account_b,
                instance,
            },
        ];

        let reports =
            detect_unattributed_orphaned_resources(&[], &scanned, &[account_a.organization_id]);

        assert_eq!(reports.len(), 1);
        match &reports[0].drift_type {
            DriftType::OrphanedInAws(id) => assert_eq!(id, "i-456"),
            _ => panic!("Expected OrphanedInAws drift type"),
        }
        assert_eq!(reports[0].severity, DriftSeverity::Info);
        assert!(
            reports[0]
                .description
                .contains("could not be attributed to any organization")
        );
        assert!(reports[0].description.contains("123456789012"));
    }

    #[test]
    fn test_unattributed_caution_managed_instance_is_critical() {
        let account = test_account();
        let scanned = vec![ScannedInstance {
            account: account.clone(),
            instance: tagged_instance("i-456", tags(&[("ManagedBy", "caution+tofu")])),
        }];

        let reports =
            detect_unattributed_orphaned_resources(&[], &scanned, &[account.organization_id]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].severity, DriftSeverity::Critical);
        assert!(
            reports[0]
                .description
                .contains("appears to be a Caution deployment")
        );
    }

    #[test]
    fn test_unattributed_instance_tagged_with_known_org_not_reported() {
        let account = test_account();
        let instance = tagged_instance(
            "i-456",
            tags(&[
                ("org_id", &account.organization_id.to_string()),
                ("ManagedBy", "caution+tofu"),
            ]),
        );
        let scanned = vec![ScannedInstance {
            account: account.clone(),
            instance,
        }];

        let reports =
            detect_unattributed_orphaned_resources(&[], &scanned, &[account.organization_id]);

        assert!(
            reports.is_empty(),
            "an instance owned by a known organization is not unattributed"
        );
    }

    #[test]
    fn test_unattributed_instance_matching_known_resource_not_reported() {
        let account = test_account();
        let resource_uuid = uuid::Uuid::new_v4();
        let db_resources = vec![tagged_resource(
            &account,
            resource_uuid,
            "i-999",
            ResourceState::Running,
        )];
        let instance =
            tagged_instance("i-456", tags(&[("ResourceId", &resource_uuid.to_string())]));
        let scanned = vec![ScannedInstance {
            account: account.clone(),
            instance,
        }];

        let reports = detect_unattributed_orphaned_resources(
            &db_resources,
            &scanned,
            &[account.organization_id],
        );

        assert!(
            reports.is_empty(),
            "a resource-owned instance is not unattributed"
        );
    }

    #[test]
    fn test_unattributed_tracked_instance_not_reported() {
        let account = test_account();
        let db_resources = vec![tracked_resource(&account, "i-456", ResourceState::Running)];
        let scanned = vec![ScannedInstance {
            account: account.clone(),
            instance: tagged_instance("i-456", HashMap::new()),
        }];

        let reports = detect_unattributed_orphaned_resources(
            &db_resources,
            &scanned,
            &[account.organization_id],
        );

        assert!(reports.is_empty(), "a tracked instance is not unattributed");
    }

    #[test]
    fn test_unattributed_stale_org_id_reported() {
        let account = test_account();
        let scanned = vec![ScannedInstance {
            account: account.clone(),
            instance: tagged_instance(
                "i-456",
                tags(&[("org_id", "550e8400-e29b-41d4-a716-446655440000")]),
            ),
        }];

        let reports =
            detect_unattributed_orphaned_resources(&[], &scanned, &[account.organization_id]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].severity, DriftSeverity::Info);
        assert!(
            reports[0]
                .description
                .contains("could not be attributed to any organization")
        );
    }

    #[test]
    fn test_classify_caution_resource_matches_platform_tag_scheme() {
        assert_eq!(
            classify_caution_resource(&tags(&[("ManagedBy", "caution-builder")])),
            Some(CautionResourceKind::Builder)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("BuildId", "b-123")])),
            Some(CautionResourceKind::Builder)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("Name", "caution-builder-abc12345")])),
            Some(CautionResourceKind::Builder)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[(
                "ResourceId",
                "550e8400-e29b-41d4-a716-446655440000"
            )])),
            Some(CautionResourceKind::Deployment)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("ManagedBy", "caution+tofu")])),
            Some(CautionResourceKind::Deployment)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("ConfigDomain", "app.example.com")])),
            Some(CautionResourceKind::Deployment)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("caution:deployment-id", "dep-1")])),
            Some(CautionResourceKind::Deployment)
        );
        assert_eq!(
            classify_caution_resource(&tags(&[("caution:resource_id", "cr-123")])),
            Some(CautionResourceKind::Deployment)
        );
        assert_eq!(classify_caution_resource(&HashMap::new()), None);
        assert_eq!(
            classify_caution_resource(&tags(&[("ManagedBy", "CloudFormation")])),
            None
        );
    }

    #[test]
    fn test_classify_builder_takes_precedence_over_deployment_markers() {
        assert_eq!(
            classify_caution_resource(&tags(&[
                ("ManagedBy", "caution-builder"),
                ("caution:deployment-id", "dep-1"),
            ])),
            Some(CautionResourceKind::Builder)
        );
    }

    #[test]
    fn test_missing_resource_severity_reflects_expected_state() {
        let running = create_test_resource("i-running", ResourceState::Running);
        let drifts = detect_resource_drift(&running, None);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, DriftSeverity::Critical);

        let stopped = create_test_resource("i-stopped", ResourceState::Stopped);
        let drifts = detect_resource_drift(&stopped, None);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, DriftSeverity::Warning);

        let failed = create_test_resource("i-failed", ResourceState::Failed);
        let drifts = detect_resource_drift(&failed, None);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, DriftSeverity::Warning);

        let pending = create_test_resource("i-pending", ResourceState::Pending);
        let drifts = detect_resource_drift(&pending, None);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, DriftSeverity::Info);

        let initialized = create_test_resource("i-initialized", ResourceState::Initialized);
        let drifts = detect_resource_drift(&initialized, None);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].severity, DriftSeverity::Info);
    }

    #[test]
    fn test_missing_terminated_resource_is_not_drift() {
        let terminated = create_test_resource("i-terminated", ResourceState::Terminated);
        let drifts = detect_resource_drift(&terminated, None);
        assert!(
            drifts.is_empty(),
            "a terminated resource missing in AWS is consistent, not drift"
        );
    }

    #[test]
    fn test_drift_severity_from_str() {
        assert_eq!("info".parse::<DriftSeverity>(), Ok(DriftSeverity::Info));
        assert_eq!("INFO".parse::<DriftSeverity>(), Ok(DriftSeverity::Info));
        assert_eq!(
            "warning".parse::<DriftSeverity>(),
            Ok(DriftSeverity::Warning)
        );
        assert_eq!("warn".parse::<DriftSeverity>(), Ok(DriftSeverity::Warning));
        assert_eq!(
            "critical".parse::<DriftSeverity>(),
            Ok(DriftSeverity::Critical)
        );
        assert!("bogus".parse::<DriftSeverity>().is_err());
    }

    #[test]
    fn test_db_state_conversion() {
        use aws_sdk_ec2::types::InstanceStateName;

        assert_eq!(
            db_state_from_aws(&InstanceStateName::Running),
            ResourceState::Running
        );
        assert_eq!(
            db_state_from_aws(&InstanceStateName::Pending),
            ResourceState::Pending
        );
        assert_eq!(
            db_state_from_aws(&InstanceStateName::Stopping),
            ResourceState::Stopped
        );
        assert_eq!(
            db_state_from_aws(&InstanceStateName::ShuttingDown),
            ResourceState::Stopped
        );
        assert_eq!(
            db_state_from_aws(&InstanceStateName::Stopped),
            ResourceState::Stopped
        );
        assert_eq!(
            db_state_from_aws(&InstanceStateName::Terminated),
            ResourceState::Terminated
        );
    }

    #[test]
    fn test_drift_summary_display() {
        let summary = DriftSummary {
            missing_in_aws: 2,
            orphaned_in_aws: 1,
            state_mismatches: 0,
            ip_mismatches: 3,
            instance_type_mismatches: 0,
        };

        let display = format!("{}", summary);
        assert!(display.contains("2 missing in AWS"));
        assert!(display.contains("1 orphaned in AWS"));
        assert!(display.contains("3 IP mismatches"));
    }

    #[test]
    fn test_drift_report_display() {
        let drift = DriftReport::new(
            DriftType::MissingInAws("i-123".to_string()),
            "Resource missing in AWS".to_string(),
            DriftSeverity::Critical,
        );

        let display = format!("{}", drift);
        assert!(display.contains("[CRITICAL]"));
        assert!(display.contains("resource"));
        assert!(display.contains("i-123"));
    }

    #[test]
    fn test_format_drift_report_includes_accounts_and_sorts() {
        let account = crate::db::ProviderAccount {
            id: uuid::Uuid::new_v4(),
            organization_id: uuid::Uuid::new_v4(),
            external_account_id: "123456789012".to_string(),
            role_arn: Some("arn:aws:iam::123456789012:role/caution".to_string()),
            region: "us-west-2".to_string(),
        };

        let drifts = vec![
            DriftReport::new(
                DriftType::OrphanedInAws("i-456".to_string()),
                "untracked".to_string(),
                DriftSeverity::Info,
            ),
            DriftReport::new(
                DriftType::MissingInAws("i-123".to_string()),
                "missing".to_string(),
                DriftSeverity::Critical,
            ),
        ];

        let report =
            OrganizationDriftReport::new(uuid::Uuid::new_v4(), vec![account], vec![], drifts);

        let formatted = format_drift_report(&report);

        assert!(formatted.contains("123456789012"));
        assert!(formatted.contains("us-west-2"));
        assert!(formatted.contains("role: arn:aws:iam::123456789012:role/caution"));
        assert!(!formatted.contains("Users:"), "no users section when empty");
        let missing = formatted.find("i-123").expect("missing resource listed");
        let orphaned = formatted.find("i-456").expect("orphaned resource listed");
        assert!(missing < orphaned, "drifts should be sorted by resource ID");
    }

    #[test]
    fn test_format_drift_report_includes_users_with_optional_emails() {
        let users = vec![
            OrgUser {
                username: "alice".to_string(),
                email: Some("alice@example.com".to_string()),
            },
            OrgUser {
                username: "bob".to_string(),
                email: None,
            },
        ];

        let report = OrganizationDriftReport::new(
            uuid::Uuid::new_v4(),
            vec![],
            users,
            vec![DriftReport::new(
                DriftType::MissingInAws("i-123".to_string()),
                "missing".to_string(),
                DriftSeverity::Critical,
            )],
        );

        let formatted = format_drift_report(&report);

        assert!(formatted.contains("Users:"));
        assert!(formatted.contains("  - alice (alice@example.com)"));
        assert!(formatted.contains("  - bob"));
    }

    #[test]
    fn test_format_org_users_omits_section_when_empty() {
        assert_eq!(format_org_users(&[]), "");
    }

    #[test]
    fn test_missing_resource_description_includes_details() {
        let mut expected = create_test_resource("i-123", ResourceState::Running);
        expected.region = Some("eu-west-1".to_string());
        expected.public_ip = Some("1.2.3.4".to_string());
        expected.configuration = Some(serde_json::json!({ "instance_type": "c5.xlarge" }));

        let drifts = detect_resource_drift(&expected, None);

        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].description.contains("eu-west-1"));
        assert!(drifts[0].description.contains("c5.xlarge"));
        assert!(drifts[0].description.contains("1.2.3.4"));
    }
}

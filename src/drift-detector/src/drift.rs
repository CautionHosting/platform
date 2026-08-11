// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core drift detection logic.
//!
//! This module provides the main functionality for comparing expected state
//! (from database) with actual state (from AWS) and reporting differences.

use crate::aws::Ec2Instance;
use crate::db::{ComputeResource, ProviderAccount, ResourceState};
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

    /// All detected drifts.
    pub drifts: Vec<DriftReport>,

    /// Summary counts.
    pub summary: DriftSummary,
}

impl OrganizationDriftReport {
    /// Create a new organization drift report from the scanned accounts and
    /// the drifts detected across them.
    #[must_use]
    pub fn new(
        org_id: uuid::Uuid,
        accounts: Vec<ProviderAccount>,
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
            drifts,
            summary,
        }
    }

    /// Keep only drifts at or above `min_severity`, recomputing the summary.
    ///
    /// Account information is preserved.
    #[must_use]
    pub fn with_severity(self, min_severity: DriftSeverity) -> Self {
        let filtered_drifts = self
            .drifts
            .into_iter()
            .filter(|d| d.severity >= min_severity)
            .collect();

        OrganizationDriftReport::new(self.org_id, self.accounts, filtered_drifts)
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
        if !db_resource_ids.contains(&instance.instance_id) {
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

/// Build the database-match clause for an orphaned instance's description.
///
/// The `ResourceId` tag (or its legacy `caution:resource_id` alias) holds the
/// database resource UUID. When the tag is absent — builders do not carry one
/// — no clause is emitted. When it is present, the report names the matching
/// resource and its expected state, or notes that no row matches.
fn describe_db_match(instance: &Ec2Instance, db_resources: &[ComputeResource]) -> String {
    let Some(tagged_resource_id) = instance
        .tags
        .get(RESOURCE_ID_TAG)
        .or_else(|| instance.tags.get(LEGACY_RESOURCE_ID_TAG))
    else {
        return String::new();
    };

    let matched = uuid::Uuid::parse_str(tagged_resource_id)
        .ok()
        .and_then(|resource_uuid| {
            db_resources
                .iter()
                .find(|resource| resource.id == resource_uuid)
        });

    match matched {
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
            format!("; no matching database resource for tagged resource id '{tagged_resource_id}'")
        }
    }
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

/// Format drift reports for display.
///
/// The report lists the scanned provider accounts, the drift summary, and each
/// drift ordered by resource ID.
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

    /// A resource with a known database ID, so the `ResourceId` tag lookup can
    /// match it.
    fn tagged_resource(
        resource_uuid: uuid::Uuid,
        instance_id: &str,
        state: ResourceState,
    ) -> ComputeResource {
        ComputeResource {
            id: resource_uuid,
            organization_id: uuid::Uuid::new_v4(),
            provider_account_id: uuid::Uuid::new_v4(),
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

    fn orphaned_from(db_resources: &[ComputeResource], instance: Ec2Instance) -> DriftReport {
        let orphaned = detect_orphaned_resources(db_resources, &[instance], &test_account());
        assert_eq!(orphaned.len(), 1);
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
        // `caution:resource_id` was never emitted by the current platform but
        // is recognized for backward compatibility.
        let db_resources = vec![create_test_resource("i-123", ResourceState::Running)];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("caution:resource_id", "cr-123")])),
        );

        assert_eq!(report.severity, DriftSeverity::Critical);
        assert!(report.description.contains("Caution deployment"));
    }

    #[test]
    fn test_orphaned_untagged_instance_is_info() {
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
        // Managed on-prem builders carry both `ManagedBy: caution-builder`
        // and `caution:deployment-id`; builder markers take precedence.
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
        let resource_uuid = uuid::Uuid::new_v4();
        let db_resources = vec![
            create_test_resource("i-123", ResourceState::Running),
            tagged_resource(resource_uuid, "i-999", ResourceState::Running),
        ];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ResourceId", &resource_uuid.to_string())])),
        );

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
        let resource_uuid = uuid::Uuid::new_v4();
        let db_resources = vec![
            create_test_resource("i-123", ResourceState::Running),
            tagged_resource(resource_uuid, "i-999", ResourceState::Stopped),
        ];
        let report = orphaned_from(
            &db_resources,
            tagged_instance("i-456", tags(&[("ResourceId", &resource_uuid.to_string())])),
        );

        assert!(report.description.contains("expected state: stopped"));
    }

    #[test]
    fn test_orphaned_builder_has_no_db_match_clause() {
        // Builders do not carry a `ResourceId` tag, so no database match is
        // attempted and the description has no match clause.
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

        let report = OrganizationDriftReport::new(uuid::Uuid::new_v4(), vec![account], drifts);

        let formatted = format_drift_report(&report);

        assert!(formatted.contains("123456789012"));
        assert!(formatted.contains("us-west-2"));
        assert!(formatted.contains("role: arn:aws:iam::123456789012:role/caution"));
        let missing = formatted.find("i-123").expect("missing resource listed");
        let orphaned = formatted.find("i-456").expect("orphaned resource listed");
        assert!(missing < orphaned, "drifts should be sorted by resource ID");
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

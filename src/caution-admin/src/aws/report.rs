// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fmt;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::Client as StsClient;
use chrono::{DateTime, Utc};
use drift_detector::drift::DriftSeverity;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use serde::Serialize;

use super::{
    AwsFinding, AwsOverviewMetadata, AwsSnapshot, cost::CostSnapshot, inventory, reconcile,
};
use crate::{db::Database, model::ResourceSummary};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingsCoverage {
    Complete,
    Partial,
    Unavailable,
}

impl fmt::Display for FindingsCoverage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        })
    }
}

impl From<DriftSeverity> for FindingSeverity {
    fn from(severity: DriftSeverity) -> Self {
        match severity {
            DriftSeverity::Info => Self::Info,
            DriftSeverity::Warning => Self::Warning,
            DriftSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingReport {
    pub severity: FindingSeverity,
    pub kind: String,
    pub issue: String,
    pub subject: String,
    pub platform_expected: String,
    pub aws_observed: String,
    pub scope: Option<String>,
    pub host_id: Option<String>,
    pub linked_resources: Vec<ResourceSummary>,
    pub next_step: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingsReport {
    pub account: Option<String>,
    pub principal: Option<String>,
    pub identity_error: Option<String>,
    pub coverage: FindingsCoverage,
    pub coverage_details: String,
    pub updated_at: String,
    pub findings: Vec<FindingReport>,
}

pub async fn load_findings_report(
    database: &Database,
) -> Result<FindingsReport, LoadFindingsReportError> {
    use LoadFindingsReportErrorCtx as Ctx;

    let region = RegionProviderChain::default_provider().or_else("us-west-2");
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let sts = StsClient::new(&config);
    let (database_state, identity, inventory) = tokio::join!(
        database.load_aws_state(),
        super::fetch_identity(&sts),
        inventory::fetch_inventory(&config),
    );
    let database_state = database_state.with_context(Ctx::database())?;
    let updated_at = Utc::now();
    let coverage_details = instance_coverage_details(&inventory);
    let snapshot = reconcile::build_snapshot(
        database_state,
        identity,
        inventory,
        CostSnapshot::default(),
        updated_at,
    );
    Ok(report_from_snapshot(snapshot, updated_at, coverage_details))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LoadFindingsReportError {
    #[error("failed to load Platform state for AWS findings [{location:?}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn report_from_snapshot(
    snapshot: AwsSnapshot,
    updated_at: DateTime<Utc>,
    coverage_details: String,
) -> FindingsReport {
    let AwsSnapshot {
        metadata,
        findings,
        identity_available,
        instances_available,
        instances_complete,
        ..
    } = snapshot;
    let coverage = match (instances_available, instances_complete, identity_available) {
        (false, _, _) => FindingsCoverage::Unavailable,
        (true, true, true) => FindingsCoverage::Complete,
        _ => FindingsCoverage::Partial,
    };
    let (account, principal, identity_error) = identity_fields(&metadata, identity_available);
    FindingsReport {
        account,
        principal,
        identity_error,
        coverage,
        coverage_details,
        updated_at: updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        findings: findings.into_iter().map(FindingReport::from).collect(),
    }
}

fn instance_coverage_details(
    inventory: &Result<inventory::InventorySnapshot, inventory::FetchInventoryError>,
) -> String {
    match inventory {
        Ok(inventory) => {
            let summary = format!(
                "{} of {} regional instance scans succeeded",
                inventory.instance_regions_succeeded, inventory.regions_scanned
            );
            let failures = inventory
                .issues
                .iter()
                .filter(|issue| issue.component == "instances")
                .map(|issue| {
                    format!(
                        "{}: {}",
                        issue.region.as_deref().unwrap_or("unknown region"),
                        issue.reason
                    )
                })
                .collect::<Vec<_>>();
            if failures.is_empty() {
                summary
            } else {
                format!("{summary} · failed: {}", failures.join(", "))
            }
        }
        Err(error) if inventory::error_chain_contains(error, "accessdenied") => {
            "enabled-region discovery access denied".to_string()
        }
        Err(inventory::FetchInventoryError::Timeout { .. }) => {
            "enabled-region discovery timed out".to_string()
        }
        Err(_) => "enabled-region discovery failed".to_string(),
    }
}

fn identity_fields(
    metadata: &AwsOverviewMetadata,
    available: bool,
) -> (Option<String>, Option<String>, Option<String>) {
    if available {
        (
            Some(metadata.account.clone()),
            Some(metadata.principal.clone()),
            None,
        )
    } else {
        (None, None, Some(metadata.principal.clone()))
    }
}

impl From<AwsFinding> for FindingReport {
    fn from(finding: AwsFinding) -> Self {
        Self {
            severity: finding.severity.into(),
            kind: finding.kind.code().to_string(),
            issue: finding.kind.label().to_string(),
            subject: finding.subject,
            platform_expected: finding.platform,
            aws_observed: finding.aws,
            scope: finding.scope,
            host_id: finding.host_id,
            linked_resources: finding.resources,
            next_step: finding.kind.next_step().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws::FindingKind;
    use chrono::TimeZone as _;

    fn snapshot(
        identity_available: bool,
        instances_available: bool,
        instances_complete: bool,
        findings: Vec<AwsFinding>,
    ) -> AwsSnapshot {
        AwsSnapshot {
            metadata: AwsOverviewMetadata {
                account: "123456789012".into(),
                principal: if identity_available {
                    "admin".into()
                } else {
                    "access denied".into()
                },
                regions: "17 scanned · 2 with resources · 0 partial failures".into(),
                updated: "ignored".into(),
                status: "ignored".into(),
            },
            overview: Vec::new(),
            app_hosts: Vec::new(),
            builders: Vec::new(),
            hosts: Vec::new(),
            storage: Vec::new(),
            findings,
            costs: Vec::new(),
            cost_snapshot: CostSnapshot::default(),
            byoc: Vec::new(),
            stale_reason: None,
            identity_available,
            inventory_available: instances_available,
            inventory_complete: instances_complete,
            instances_available,
            instances_complete,
            costs_available: false,
        }
    }

    fn finding() -> AwsFinding {
        AwsFinding {
            severity: DriftSeverity::Critical,
            kind: FindingKind::ExpectedHostAbsent,
            subject: "demo".into(),
            platform: "running app expects i-123".into(),
            aws: "EC2 not observed".into(),
            scope: Some("account 123456789012".into()),
            host_id: Some("i-123".into()),
            resources: Vec::new(),
        }
    }

    #[test]
    fn coverage_reflects_identity_and_instance_scans() {
        let updated = Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap();
        for (identity, available, complete, expected) in [
            (true, true, true, FindingsCoverage::Complete),
            (false, true, true, FindingsCoverage::Partial),
            (true, true, false, FindingsCoverage::Partial),
            (true, false, false, FindingsCoverage::Unavailable),
        ] {
            let report = report_from_snapshot(
                snapshot(identity, available, complete, vec![finding()]),
                updated,
                "instance coverage".into(),
            );
            assert_eq!(report.coverage, expected);
        }
    }

    #[test]
    fn unavailable_ec2_keeps_platform_only_findings() {
        let updated = Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap();
        let mut finding = finding();
        finding.kind = FindingKind::InvalidAccountMapping;
        finding.host_id = None;
        let report = report_from_snapshot(
            snapshot(true, false, false, vec![finding]),
            updated,
            "0 of 17 regional instance scans succeeded".into(),
        );
        assert_eq!(report.coverage, FindingsCoverage::Unavailable);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, "invalid_account_mapping");
    }

    #[test]
    fn instance_coverage_ignores_other_inventory_failures() {
        let inventory = inventory::InventorySnapshot {
            regions_scanned: 2,
            instance_regions_succeeded: 2,
            issues: vec![inventory::InventoryIssue {
                component: "volumes",
                region: Some("us-west-2".into()),
                reason: "access denied".into(),
            }],
            ..inventory::InventorySnapshot::default()
        };
        assert_eq!(
            instance_coverage_details(&Ok(inventory)),
            "2 of 2 regional instance scans succeeded"
        );
    }

    #[test]
    fn instance_coverage_names_failed_regions() {
        let inventory = inventory::InventorySnapshot {
            regions_scanned: 2,
            instance_regions_succeeded: 1,
            issues: vec![inventory::InventoryIssue {
                component: "instances",
                region: Some("eu-west-1".into()),
                reason: "timed out".into(),
            }],
            ..inventory::InventorySnapshot::default()
        };
        assert_eq!(
            instance_coverage_details(&Ok(inventory)),
            "1 of 2 regional instance scans succeeded · failed: eu-west-1: timed out"
        );
    }

    #[test]
    fn report_has_stable_machine_fields() {
        let updated = Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap();
        let report = report_from_snapshot(
            snapshot(true, true, true, vec![finding()]),
            updated,
            "17 of 17 regional instance scans succeeded".into(),
        );
        let value = serde_json::to_value(report).expect("serialize report");
        assert_eq!(value["coverage"], "complete");
        assert_eq!(value["updated_at"], "2026-09-03T12:00:00Z");
        assert_eq!(value["findings"][0]["severity"], "critical");
        assert_eq!(value["findings"][0]["kind"], "expected_host_absent");
        assert_eq!(
            value["findings"][0]["issue"],
            "App expects EC2; none observed"
        );
        assert!(value["findings"][0]["next_step"].is_string());
        assert!(value["findings"][0]["linked_resources"].is_array());
        let envelope_keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            envelope_keys,
            [
                "account",
                "coverage",
                "coverage_details",
                "findings",
                "identity_error",
                "principal",
                "updated_at",
            ]
        );
        let finding_keys = value["findings"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            finding_keys,
            [
                "aws_observed",
                "host_id",
                "issue",
                "kind",
                "linked_resources",
                "next_step",
                "platform_expected",
                "scope",
                "severity",
                "subject",
            ]
        );
        assert!(value["identity_error"].is_null());

        let mut optional_fields = finding();
        optional_fields.scope = None;
        optional_fields.host_id = None;
        let value = serde_json::to_value(FindingReport::from(optional_fields)).unwrap();
        assert!(value["scope"].is_null());
        assert!(value["host_id"].is_null());
    }

    #[test]
    fn unavailable_identity_is_not_presented_as_a_principal() {
        let updated = Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap();
        let report = report_from_snapshot(
            snapshot(false, true, true, Vec::new()),
            updated,
            "17 of 17 regional instance scans succeeded".into(),
        );
        assert_eq!(report.account, None);
        assert_eq!(report.principal, None);
        assert_eq!(report.identity_error.as_deref(), Some("access denied"));
    }

    #[test]
    fn report_does_not_limit_findings() {
        let updated = Utc.with_ymd_and_hms(2026, 9, 3, 12, 0, 0).unwrap();
        let report = report_from_snapshot(
            snapshot(true, true, true, vec![finding(); 61]),
            updated,
            "17 of 17 regional instance scans succeeded".into(),
        );
        assert_eq!(report.findings.len(), 61);
        assert_eq!(
            serde_json::to_value(report).unwrap()["findings"]
                .as_array()
                .unwrap()
                .len(),
            61
        );
    }

    #[test]
    fn finding_kind_codes_are_stable() {
        let codes = [
            (FindingKind::ExpectedHostAbsent, "expected_host_absent"),
            (FindingKind::HostForTerminatedApp, "host_for_terminated_app"),
            (FindingKind::UnexpectedHost, "unexpected_host"),
            (FindingKind::StateMismatch, "state_mismatch"),
            (FindingKind::UntrackedHost, "untracked_host"),
            (FindingKind::LinkMismatch, "link_mismatch"),
            (FindingKind::AmbiguousAssociation, "ambiguous_association"),
            (
                FindingKind::InvalidAccountMapping,
                "invalid_account_mapping",
            ),
            (FindingKind::AccountMismatch, "account_mismatch"),
            (FindingKind::OrphanBuilder, "orphan_builder"),
        ];
        for (kind, expected) in codes {
            assert_eq!(kind.code(), expected);
        }
    }
}

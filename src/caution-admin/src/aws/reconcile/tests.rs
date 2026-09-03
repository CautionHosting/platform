// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::{
    aws::{
        AccountIdentity, FindingKind,
        cost::{CostLine, CostSnapshot},
        inventory::{AwsAddress, AwsInstance, AwsVolume, InventoryIssue},
    },
    db::aws::{AwsAppRow, AwsBuildRow, AwsDatabaseState, ByocSubscriptionRow},
};

const ACCOUNT: &str = "123456789012";

fn app(name: &str, state: &str, byoc: bool) -> AwsAppRow {
    AwsAppRow {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        organization_name: "Acme".to_string(),
        name: name.to_string(),
        state: state.to_string(),
        aws_account_id: ACCOUNT.to_string(),
        provider_resource_id: format!("i-{name}"),
        region: Some("us-west-2".to_string()),
        public_ip: None,
        managed_on_prem: byoc,
        destroyed: state == "terminated",
    }
}

fn instance(app: &AwsAppRow, state: &str) -> AwsInstance {
    AwsInstance {
        instance_id: app.provider_resource_id.clone(),
        region: "us-west-2".to_string(),
        availability_zone: Some("us-west-2a".to_string()),
        launch_time_epoch_secs: Some(1_788_000_000),
        instance_type: Some("m6i.xlarge".to_string()),
        state: state.to_string(),
        public_ip: None,
        private_ip: Some("10.0.0.10".to_string()),
        vpc_id: Some("vpc-1".to_string()),
        subnet_id: Some("subnet-1".to_string()),
        tags: HashMap::from([
            ("ManagedBy".to_string(), "caution+tofu".to_string()),
            ("ResourceId".to_string(), app.id.to_string()),
        ]),
    }
}

fn snapshot(database: AwsDatabaseState, inventory: InventorySnapshot) -> AwsSnapshot {
    build_snapshot(
        database,
        Ok(AccountIdentity {
            account: ACCOUNT.into(),
            principal: "admin".into(),
        }),
        Ok(inventory),
        CostSnapshot::default(),
        Utc::now(),
    )
}

fn database(apps: Vec<AwsAppRow>) -> AwsDatabaseState {
    AwsDatabaseState {
        apps,
        builds: Vec::new(),
        byoc: Vec::new(),
    }
}

fn has(snapshot: &AwsSnapshot, kind: FindingKind, severity: DriftSeverity) -> bool {
    snapshot
        .findings
        .iter()
        .any(|finding| finding.kind == kind && finding.severity == severity)
}

#[test]
fn lifecycle_rules_only_flag_confirmed_host_expectations() {
    let pending = app("pending", "pending", false);
    let initialized = app("initialized", "initialized", false);
    let terminating = app("terminating", "terminating", false);
    let failed = app("failed", "failed", false);
    let running = app("running", "running", false);
    let stopped = app("stopped", "stopped", false);
    let snapshot = snapshot(
        database(vec![
            pending,
            initialized,
            terminating,
            failed,
            running,
            stopped,
        ]),
        InventorySnapshot::default(),
    );
    let missing = snapshot
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::ExpectedHostAbsent)
        .collect::<Vec<_>>();
    assert_eq!(missing.len(), 2);
    assert_eq!(missing[0].severity, DriftSeverity::Critical);
    assert_eq!(missing[1].severity, DriftSeverity::Warning);
}

#[test]
fn exact_hosts_apply_lifecycle_and_state_rules() {
    let terminated = app("terminated", "terminated", false);
    let initialized = app("initialized", "initialized", false);
    let running = app("running", "running", false);
    let stopped = app("stopped", "stopped", false);
    let inventory = InventorySnapshot {
        instances: vec![
            instance(&terminated, "running"),
            instance(&initialized, "running"),
            instance(&running, "stopped"),
            instance(&stopped, "running"),
        ],
        ..InventorySnapshot::default()
    };
    let snapshot = snapshot(
        database(vec![terminated, initialized, running, stopped]),
        inventory,
    );
    assert!(has(
        &snapshot,
        FindingKind::HostForTerminatedApp,
        DriftSeverity::Critical
    ));
    assert!(has(
        &snapshot,
        FindingKind::UnexpectedHost,
        DriftSeverity::Warning
    ));
    assert!(has(
        &snapshot,
        FindingKind::StateMismatch,
        DriftSeverity::Critical
    ));
    assert!(has(
        &snapshot,
        FindingKind::StateMismatch,
        DriftSeverity::Warning
    ));
    assert!(
        snapshot
            .app_hosts
            .iter()
            .all(|row| matches!(&row.action, AwsAction::Host(_)))
    );
    assert!(
        snapshot
            .app_hosts
            .iter()
            .all(|row| !row.details.starts_with("failed"))
    );
}

#[test]
fn exact_id_wins_and_tag_only_host_does_not_suppress_missing() {
    let exact = app("exact", "running", false);
    let tagged = app("tagged", "running", false);
    let mut exact_host = instance(&exact, "running");
    exact_host
        .tags
        .insert("ResourceId".into(), tagged.id.to_string());
    let mut tag_only = instance(&tagged, "running");
    tag_only.instance_id = "i-stale".to_string();
    let snapshot = snapshot(
        database(vec![exact.clone(), tagged.clone()]),
        InventorySnapshot {
            instances: vec![exact_host, tag_only],
            ..InventorySnapshot::default()
        },
    );
    assert!(
        matches!(&snapshot.app_hosts[0].action, AwsAction::Host(id) if id == &exact.provider_resource_id)
    );
    assert!(matches!(snapshot.app_hosts[1].action, AwsAction::Host(_)));
    assert!(has(
        &snapshot,
        FindingKind::LinkMismatch,
        DriftSeverity::Warning
    ));
    assert!(snapshot.findings.iter().any(|finding| finding.kind
        == FindingKind::ExpectedHostAbsent
        && finding.subject == tagged.name
        && finding.host_id.as_deref() == Some("i-stale")
        && finding.aws.contains("carries this app tag")));
}

#[test]
fn account_scope_and_byoc_exclude_customer_hosts_from_absence_checks() {
    let mut other_account = app("other", "running", false);
    other_account.aws_account_id = "999999999999".to_string();
    let byoc = app("byoc", "running", true);
    let mut tagged_customer_host = instance(&byoc, "running");
    tagged_customer_host.instance_id = "i-customer-tag".to_string();
    let snapshot = snapshot(
        database(vec![other_account, byoc.clone()]),
        InventorySnapshot {
            instances: vec![tagged_customer_host],
            ..InventorySnapshot::default()
        },
    );
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].kind, FindingKind::AccountMismatch);
    assert_eq!(snapshot.findings[0].resources[0].id, byoc.id);
}

#[test]
fn unobserved_byoc_with_non_account_identifier_is_not_a_finding() {
    let mut byoc = app("byoc", "running", true);
    byoc.aws_account_id = "customer-account".to_string();

    let snapshot = snapshot(database(vec![byoc]), InventorySnapshot::default());

    assert!(snapshot.findings.is_empty());
}

#[test]
fn exact_host_with_malformed_account_is_linked_and_reported_once() {
    let mut app = app("app-a1d7331a", "initialized", false);
    app.id = Uuid::parse_str("68a5e092-6e51-42da-b201-6a70ef9d44ba").unwrap();
    app.provider_resource_id = "i-051a020411fa9d3f1".to_string();
    app.aws_account_id = "mvp-test-38ac0c26-cfa0-456e-8ff5-d3dd75e05be3".to_string();
    let host = instance(&app, "running");

    let snapshot = snapshot(
        database(vec![app.clone()]),
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.findings.len(), 1);
    let finding = &snapshot.findings[0];
    assert_eq!(finding.kind, FindingKind::InvalidAccountMapping);
    assert_eq!(finding.severity, DriftSeverity::Warning);
    assert_eq!(finding.host_id.as_deref(), Some("i-051a020411fa9d3f1"));
    assert_eq!(finding.resources[0].id, app.id);
    assert!(finding.platform.starts_with("initialized"));
    assert!(finding.aws.starts_with("running EC2"));
    assert_eq!(
        snapshot.hosts[0].platform.as_ref().unwrap().resource.id,
        app.id
    );
}

#[test]
fn malformed_account_without_an_observed_host_is_still_reported() {
    let mut app = app("invalid-scope", "running", false);
    app.aws_account_id = "mvp-test".to_string();
    let snapshot = snapshot(database(vec![app.clone()]), InventorySnapshot::default());

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(
        snapshot.findings[0].kind,
        FindingKind::InvalidAccountMapping
    );
    assert_eq!(snapshot.findings[0].resources[0].id, app.id);
    assert_eq!(snapshot.findings[0].host_id, None);
}

#[test]
fn exact_host_in_a_different_valid_account_reports_scope_not_unknown() {
    let mut app = app("cross-account", "running", false);
    app.aws_account_id = "999999999999".to_string();
    let host = instance(&app, "running");
    let snapshot = snapshot(
        database(vec![app.clone()]),
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].kind, FindingKind::AccountMismatch);
    assert_eq!(snapshot.findings[0].resources[0].id, app.id);
}

#[test]
fn critical_lifecycle_and_account_evidence_are_one_finding() {
    let mut app = app("terminated-invalid", "terminated", false);
    app.aws_account_id = "not-an-account".to_string();
    let host = instance(&app, "running");
    let snapshot = snapshot(
        database(vec![app]),
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].kind, FindingKind::HostForTerminatedApp);
    assert_eq!(snapshot.findings[0].severity, DriftSeverity::Critical);
    assert!(
        snapshot.findings[0]
            .scope
            .as_deref()
            .is_some_and(|scope| scope.contains("not a 12-digit AWS account ID"))
    );
}

#[test]
fn tagged_hosts_for_terminated_apps_use_the_observed_state_severity() {
    let terminated = app("terminated", "terminated", false);
    let mut running = instance(&terminated, "running");
    running.instance_id = "i-running-survivor".to_string();
    let mut stopped = instance(&terminated, "stopped");
    stopped.instance_id = "i-stopped-survivor".to_string();
    let snapshot = snapshot(
        database(vec![terminated]),
        InventorySnapshot {
            instances: vec![running, stopped],
            ..InventorySnapshot::default()
        },
    );

    assert!(has(
        &snapshot,
        FindingKind::HostForTerminatedApp,
        DriftSeverity::Critical
    ));
    assert!(has(
        &snapshot,
        FindingKind::HostForTerminatedApp,
        DriftSeverity::Warning
    ));
}

#[test]
fn partial_regions_suppress_absence_but_keep_positive_findings() {
    let missing = app("regional", "running", false);
    let orphaned = app("orphaned", "terminated", false);
    let snapshot = snapshot(
        database(vec![missing, orphaned.clone()]),
        InventorySnapshot {
            instances: vec![instance(&orphaned, "running")],
            issues: vec![InventoryIssue {
                component: "instances",
                region: Some("us-west-2".to_string()),
                reason: "access denied".to_string(),
            }],
            ..InventorySnapshot::default()
        },
    );
    assert!(
        !snapshot
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::ExpectedHostAbsent)
    );
    assert!(has(
        &snapshot,
        FindingKind::HostForTerminatedApp,
        DriftSeverity::Critical
    ));
    let overview = snapshot
        .overview
        .iter()
        .find(|row| row.action == AwsAction::Section(AwsSection::Findings))
        .unwrap();
    assert!(overview.name.contains("1+"));
    assert!(
        !snapshot
            .findings
            .iter()
            .any(|finding| finding.subject == "instances")
    );
}

#[test]
fn unknown_hosts_and_orphan_builders_use_observed_state_severity() {
    let unknown = |id: &str, state: &str| AwsInstance {
        instance_id: id.to_string(),
        region: "us-west-2".to_string(),
        availability_zone: None,
        launch_time_epoch_secs: None,
        instance_type: None,
        state: state.to_string(),
        public_ip: None,
        private_ip: None,
        vpc_id: None,
        subnet_id: None,
        tags: HashMap::from([("ManagedBy".to_string(), "caution+tofu".to_string())]),
    };
    let builder = |id: &str, state: &str| AwsInstance {
        tags: HashMap::from([("ManagedBy".to_string(), "caution-builder".to_string())]),
        ..unknown(id, state)
    };
    let snapshot = snapshot(
        database(Vec::new()),
        InventorySnapshot {
            instances: vec![
                unknown("i-running", "running"),
                unknown("i-stopped", "stopped"),
                builder("i-builder-running", "running"),
                builder("i-builder-pending", "pending"),
            ],
            ..InventorySnapshot::default()
        },
    );
    assert!(has(
        &snapshot,
        FindingKind::UntrackedHost,
        DriftSeverity::Critical
    ));
    assert!(has(
        &snapshot,
        FindingKind::UntrackedHost,
        DriftSeverity::Warning
    ));
    assert!(has(
        &snapshot,
        FindingKind::OrphanBuilder,
        DriftSeverity::Critical
    ));
    assert!(has(
        &snapshot,
        FindingKind::OrphanBuilder,
        DriftSeverity::Warning
    ));
    assert!(
        snapshot
            .findings
            .iter()
            .all(|finding| finding.severity != DriftSeverity::Info)
    );
}

#[test]
fn active_builder_with_a_different_tagged_instance_is_a_link_mismatch() {
    let build = AwsBuildRow {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        organization_name: "Acme".to_string(),
        app_id: None,
        app_name: None,
        builder_instance_id: Some("i-expected-builder".to_string()),
        status: "building".to_string(),
    };
    let observed = AwsInstance {
        instance_id: "i-tagged-builder".to_string(),
        tags: HashMap::from([
            ("ManagedBy".to_string(), "caution-builder".to_string()),
            ("BuildId".to_string(), build.id.to_string()),
        ]),
        ..instance(&app("fixture", "running", false), "running")
    };
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: Vec::new(),
            builds: vec![build],
            byoc: Vec::new(),
        },
        InventorySnapshot {
            instances: vec![observed],
            ..InventorySnapshot::default()
        },
    );

    assert!(has(
        &snapshot,
        FindingKind::LinkMismatch,
        DriftSeverity::Warning
    ));
    assert_eq!(
        snapshot.hosts[0].platform.as_ref().unwrap().relation,
        "BuildId tag"
    );
}

#[test]
fn byoc_rows_use_current_subscriptions_and_deploy_gate() {
    let organization_id = Uuid::new_v4();
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: Vec::new(),
            builds: Vec::new(),
            byoc: vec![ByocSubscriptionRow {
                organization_id,
                organization_name: "Acme".to_string(),
                organization_active: true,
                tier: "growth".to_string(),
                status: "active".to_string(),
                billing_source: "paddle".to_string(),
                catalog_valid: false,
                enterprise_expires_at: None,
                max_apps: 5,
                pending_tier: Some("scale".to_string()),
                pending_max_apps: Some(3),
                allocated_apps: 2,
            }],
        },
        InventorySnapshot::default(),
    );
    assert_eq!(snapshot.byoc.len(), 1);
    assert!(
        snapshot.byoc[0]
            .details
            .starts_with("inactive · subscription cannot deploy")
    );
    assert!(snapshot.byoc[0].details.contains("2 / 3 used"));
}

#[test]
fn cost_overview_counts_only_breakdown_rows() {
    let snapshot = build_snapshot(
        database(Vec::new()),
        Ok(AccountIdentity {
            account: ACCOUNT.into(),
            principal: "admin".into(),
        }),
        Ok(InventorySnapshot::default()),
        CostSnapshot {
            period: Some("current month".to_string()),
            mtd_micros: Some(10_000_000),
            forecast_micros: Some(5_000_000),
            currency: "USD".to_string(),
            services: vec![CostLine {
                name: "EC2".to_string(),
                amount_micros: 10_000_000,
                currency: "USD".to_string(),
            }],
            ..CostSnapshot::default()
        },
        Utc::now(),
    );

    assert_eq!(snapshot.costs.len(), 3);
    assert!(snapshot.overview.iter().any(|row| row.name == "Costs (1)"));
}

#[test]
fn storage_counts_only_caution_resources() {
    let managed = app("api", "running", false);
    let host = instance(&managed, "running");
    let inventory = InventorySnapshot {
        instances: vec![host.clone()],
        volumes: vec![AwsVolume {
            volume_id: "vol-1".into(),
            region: host.region.clone(),
            size_gib: 30,
            state: "in-use".into(),
            attached_instances: vec![host.instance_id.clone()],
            tags: HashMap::new(),
        }],
        addresses: vec![AwsAddress {
            allocation_id: "eipalloc-1".into(),
            public_ip: "203.0.113.1".into(),
            region: host.region,
            instance_id: None,
            tags: host.tags,
        }],
        ..InventorySnapshot::default()
    };
    let snapshot = snapshot(database(vec![managed]), inventory);
    assert_eq!(snapshot.storage.len(), 2);
    assert!(
        snapshot
            .overview
            .iter()
            .any(|row| row.name == "Storage and IPs (2)" && row.details.contains("30 GiB EBS"))
    );
}

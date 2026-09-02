// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::{
    aws::{
        AccountIdentity,
        cost::CostSnapshot,
        inventory::{AwsAddress, AwsInstance, AwsVolume},
    },
    db::aws::{AwsAppRow, AwsBuildRow, AwsDatabaseState, ByocSubscriptionRow},
    model::ResourceKind,
};

fn app(name: &str, state: &str, byoc: bool) -> AwsAppRow {
    AwsAppRow {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        organization_name: "Acme".to_string(),
        name: name.to_string(),
        state: state.to_string(),
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
        instance_type: Some("m6i.xlarge".to_string()),
        state: state.to_string(),
        public_ip: None,
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
            account: "123456789012".into(),
            principal: "admin".into(),
        }),
        Ok(inventory),
        CostSnapshot::default(),
        Utc::now(),
    )
}

#[test]
fn reconciliation_finds_missing_orphaned_and_mismatched_apps() {
    let missing = app("missing", "running", false);
    let terminated = app("terminated", "terminated", false);
    let mismatched = app("mismatch", "running", false);
    let database = AwsDatabaseState {
        apps: vec![missing, terminated.clone(), mismatched.clone()],
        builds: Vec::new(),
        byoc: Vec::new(),
    };
    let inventory = InventorySnapshot {
        regions_scanned: 1,
        regions_with_resources: 1,
        instances: vec![
            instance(&terminated, "running"),
            instance(&mismatched, "stopped"),
        ],
        ..InventorySnapshot::default()
    };
    let snapshot = snapshot(database, inventory);
    assert!(snapshot.drift.iter().any(|row| row.kind == "MISSING"));
    assert!(snapshot.drift.iter().any(|row| row.kind == "ORPHAN"));
    assert!(snapshot.drift.iter().any(|row| row.kind == "STATE"));
    assert!(snapshot.app_hosts.iter().all(|row| {
        matches!(&row.action, AwsAction::Resource(summary) if summary.kind == ResourceKind::App)
    }));
    assert!(snapshot.app_hosts.iter().any(|row| {
        row.name == "terminated"
            && row
                .details
                .starts_with("failed · AWS running · Platform terminated")
    }));
    assert!(snapshot.app_hosts.iter().any(|row| {
        row.name == "mismatch"
            && row
                .details
                .starts_with("warning · AWS stopped · Platform running")
    }));
    assert_eq!(snapshot.overview.len(), AwsSection::ALL.len());
    assert!(
        snapshot
            .overview
            .iter()
            .all(|row| row.kind == "AWS" && matches!(row.action, AwsAction::Section(_)))
    );
    assert_eq!(snapshot.metadata.account, "123456789012");
    assert_eq!(snapshot.metadata.principal, "admin");
}

#[test]
fn tag_only_host_is_diagnostic_and_does_not_hide_missing_app() {
    let managed = app("api", "running", false);
    let mut stale_host = instance(&managed, "running");
    stale_host.instance_id = "i-stale-host".to_string();
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: vec![managed.clone()],
            builds: Vec::new(),
            byoc: Vec::new(),
        },
        InventorySnapshot {
            instances: vec![stale_host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.app_hosts[0].name, "i-stale-host");
    assert_eq!(snapshot.app_hosts[0].action, AwsAction::None);
    assert!(snapshot.app_hosts[0].details.contains("tagged app api"));
    assert!(snapshot.drift.iter().any(|row| {
        row.kind == "LINK"
            && matches!(
                &row.action,
                AwsAction::Resource(summary) if summary.id == managed.id
            )
    }));
    assert!(snapshot.drift.iter().any(|row| row.kind == "MISSING"));
}

#[test]
fn running_host_tagged_for_terminated_app_is_explicit_failed_drift() {
    let terminated = app("steve-nitro-test-app", "terminated", false);
    let mut host = instance(&terminated, "running");
    host.instance_id = "i-0677cd6d2bda4796f".to_string();
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: vec![terminated.clone()],
            builds: Vec::new(),
            byoc: Vec::new(),
        },
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.app_hosts[0].action, AwsAction::None);
    assert!(
        snapshot.app_hosts[0]
            .details
            .starts_with("failed · AWS running · tagged app steve-nitro-test-app is terminated")
    );
    assert!(snapshot.drift.iter().any(|row| {
        row.kind == "LINK"
            && row.details.starts_with("failed · AWS running")
            && matches!(
                &row.action,
                AwsAction::Resource(summary) if summary.id == terminated.id
            )
    }));
}

#[test]
fn exact_instance_match_wins_over_conflicting_resource_tag() {
    let exact = app("exact", "running", false);
    let tagged = app("tagged", "terminated", false);
    let mut host = instance(&exact, "running");
    host.tags
        .insert("ResourceId".to_string(), tagged.id.to_string());
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: vec![exact.clone(), tagged.clone()],
            builds: Vec::new(),
            byoc: Vec::new(),
        },
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert!(matches!(
        &snapshot.app_hosts[0].action,
        AwsAction::Resource(summary) if summary.id == exact.id
    ));
    assert!(snapshot.drift.iter().any(|row| {
        row.kind == "LINK"
            && matches!(
                &row.action,
                AwsAction::Resource(summary) if summary.id == tagged.id
            )
    }));
}

#[test]
fn byoc_apps_are_not_reported_missing_from_the_managed_account() {
    let byoc = app("customer", "running", true);
    let database = AwsDatabaseState {
        apps: vec![byoc.clone()],
        builds: Vec::new(),
        byoc: vec![ByocSubscriptionRow {
            organization_id: byoc.organization_id,
            organization_name: byoc.organization_name,
            organization_active: true,
            tier: "growth".into(),
            status: "active".into(),
            billing_source: "paddle".into(),
            max_apps: 3,
            pending_tier: None,
            pending_max_apps: None,
            allocated_apps: 1,
        }],
    };
    let snapshot = snapshot(database, InventorySnapshot::default());
    assert!(!snapshot.drift.iter().any(|row| row.kind == "MISSING"));
    assert_eq!(snapshot.byoc.len(), 1);
    assert_eq!(snapshot.byoc[0].kind, "ORGANIZATION");
    assert!(snapshot.byoc[0].details.contains("subscription active"));
    assert!(matches!(
        &snapshot.byoc[0].action,
        AwsAction::Resource(summary) if summary.kind == ResourceKind::Organization
    ));
}

#[test]
fn failed_region_scan_does_not_create_false_missing_findings() {
    let managed = app("regional", "running", false);
    let inventory = InventorySnapshot {
        regions_scanned: 1,
        issues: vec![crate::aws::inventory::InventoryIssue {
            component: "instances",
            region: managed.region.clone(),
            reason: "access denied".to_string(),
        }],
        ..InventorySnapshot::default()
    };
    let database = AwsDatabaseState {
        apps: vec![managed],
        builds: Vec::new(),
        byoc: Vec::new(),
    };
    let snapshot = snapshot(database, inventory);
    assert!(!snapshot.drift.iter().any(|row| row.kind == "MISSING"));
    assert!(snapshot.drift.iter().any(|row| row.kind == "PARTIAL"));
    assert!(snapshot.overview.iter().any(|row| {
        row.action == AwsAction::Section(AwsSection::AppHosts)
            && row.name == "App hosts (?)"
            && row.details.starts_with("warning · partial")
    }));
}

#[test]
fn reconciliation_flags_duplicate_hosts_and_terminal_builders() {
    let managed = app("api", "running", false);
    let mut duplicate = instance(&managed, "running");
    duplicate.instance_id = "i-duplicate".to_string();
    let build = AwsBuildRow {
        id: Uuid::new_v4(),
        organization_id: managed.organization_id,
        organization_name: managed.organization_name.clone(),
        app_id: Some(managed.id),
        app_name: Some(managed.name.clone()),
        builder_instance_id: Some("i-builder".to_string()),
        status: "complete".to_string(),
    };
    let builder = AwsInstance {
        instance_id: "i-builder".to_string(),
        region: "us-west-2".to_string(),
        instance_type: Some("m6i.xlarge".to_string()),
        state: "running".to_string(),
        public_ip: None,
        tags: HashMap::from([
            ("ManagedBy".to_string(), "caution-builder".to_string()),
            ("BuildId".to_string(), build.id.to_string()),
        ]),
    };
    let database = AwsDatabaseState {
        apps: vec![managed.clone()],
        builds: vec![build],
        byoc: Vec::new(),
    };
    let inventory = InventorySnapshot {
        instances: vec![instance(&managed, "running"), duplicate, builder],
        ..InventorySnapshot::default()
    };
    let snapshot = snapshot(database, inventory);
    assert!(snapshot.drift.iter().any(|row| row.kind == "DUPLICATE"));
    assert!(snapshot.drift.iter().any(|row| row.kind == "BUILDER"));
    assert!(matches!(
        &snapshot.builders[0].action,
        AwsAction::Resource(summary) if summary.kind == ResourceKind::App
    ));
}

#[test]
fn storage_counts_tagged_and_attached_resources() {
    let managed = app("api", "running", false);
    let host = instance(&managed, "running");
    let inventory = InventorySnapshot {
        instances: vec![host.clone()],
        volumes: vec![
            AwsVolume {
                volume_id: "vol-1".into(),
                region: host.region.clone(),
                size_gib: 30,
                state: "in-use".into(),
                attached_instances: vec![host.instance_id.clone()],
                tags: HashMap::new(),
            },
            AwsVolume {
                volume_id: "vol-2".into(),
                region: host.region.clone(),
                size_gib: 20,
                state: "available".into(),
                attached_instances: Vec::new(),
                tags: host.tags.clone(),
            },
        ],
        addresses: vec![
            AwsAddress {
                allocation_id: "eipalloc-1".into(),
                public_ip: "203.0.113.1".into(),
                region: host.region.clone(),
                instance_id: Some(host.instance_id),
                tags: HashMap::new(),
            },
            AwsAddress {
                allocation_id: "eipalloc-2".into(),
                public_ip: "203.0.113.2".into(),
                region: host.region,
                instance_id: None,
                tags: host.tags,
            },
        ],
        ..InventorySnapshot::default()
    };
    let database = AwsDatabaseState {
        apps: vec![managed],
        builds: Vec::new(),
        byoc: Vec::new(),
    };
    let snapshot = snapshot(database, inventory);
    assert_eq!(snapshot.storage.len(), 4);
    assert!(
        snapshot
            .storage
            .iter()
            .any(|row| { row.name == "vol-2" && row.details.starts_with("warning · 20 GiB") })
    );
    assert!(snapshot.storage.iter().any(|row| {
        row.name == "203.0.113.2" && row.details.starts_with("failed · unassociated")
    }));
    assert!(snapshot.overview.iter().any(|row| {
        row.action == AwsAction::Section(AwsSection::Storage)
            && row.details == "active · 50 GiB EBS · 1 unassociated IPs"
    }));
}

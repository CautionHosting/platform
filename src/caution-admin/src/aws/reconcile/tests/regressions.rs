// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

#[test]
fn inactive_or_destroyed_apps_do_not_emit_absent_invalid_account_findings() {
    let mut running = app("running-invalid", "running", false);
    running.aws_account_id = "invalid-running".to_string();
    let mut destroyed = app("destroyed-invalid", "running", false);
    destroyed.aws_account_id = "invalid-destroyed".to_string();
    destroyed.destroyed = true;
    let mut terminated = app("terminated-invalid", "terminated", false);
    terminated.aws_account_id = "invalid-terminated".to_string();
    let mut initialized = app("initialized-invalid", "initialized", false);
    initialized.aws_account_id = "invalid-initialized".to_string();

    let snapshot = snapshot(
        database(vec![running.clone(), destroyed, terminated, initialized]),
        InventorySnapshot::default(),
    );

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].resources[0].id, running.id);
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
fn warning_lifecycle_and_account_evidence_are_one_lifecycle_finding() {
    let mut app = app("stopped-other-account", "stopped", false);
    app.aws_account_id = "999999999999".to_string();
    let host = instance(&app, "running");
    let snapshot = snapshot(
        database(vec![app]),
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].kind, FindingKind::StateMismatch);
    assert_eq!(snapshot.findings[0].severity, DriftSeverity::Warning);
    assert!(
        snapshot.findings[0]
            .scope
            .as_deref()
            .is_some_and(|scope| scope.contains("Platform account 999999999999"))
    );
}

#[test]
fn zero_successful_instance_regions_makes_findings_unavailable() {
    let expected = app("expected", "running", false);
    let snapshot = snapshot(
        database(vec![expected]),
        InventorySnapshot {
            regions_scanned: 1,
            issues: vec![InventoryIssue {
                component: "instances",
                region: Some("us-west-2".into()),
                reason: "access denied".into(),
            }],
            ..InventorySnapshot::default()
        },
    );

    assert!(!snapshot.instances_available);
    assert!(snapshot.findings.is_empty());
    assert!(snapshot.app_hosts.is_empty());
    assert!(snapshot.overview[3].name.contains('?'));
}

#[test]
fn storage_failure_does_not_reduce_instance_finding_coverage() {
    let expected = app("expected", "running", false);
    let snapshot = snapshot(
        database(vec![expected]),
        InventorySnapshot {
            regions_scanned: 1,
            instance_regions_succeeded: 1,
            issues: vec![InventoryIssue {
                component: "volumes",
                region: Some("us-west-2".into()),
                reason: "access denied".into(),
            }],
            ..InventorySnapshot::default()
        },
    );

    assert!(snapshot.instances_complete);
    assert!(has(
        &snapshot,
        FindingKind::ExpectedHostAbsent,
        DriftSeverity::Critical
    ));
    assert_eq!(snapshot.overview[3].name, "Findings (1)");
}

#[test]
fn duplicate_exact_host_claims_are_reported_as_ambiguous() {
    let first = app("first", "running", false);
    let build = AwsBuildRow {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        organization_name: "Builder org".to_string(),
        app_id: None,
        app_name: None,
        builder_instance_id: Some(first.provider_resource_id.clone()),
        status: "building".to_string(),
    };
    let host = instance(&first, "running");
    let snapshot = snapshot(
        AwsDatabaseState {
            apps: vec![first],
            builds: vec![build],
            byoc: Vec::new(),
        },
        InventorySnapshot {
            instances: vec![host],
            ..InventorySnapshot::default()
        },
    );

    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].kind, FindingKind::AmbiguousAssociation);
    assert_eq!(snapshot.findings[0].resources.len(), 2);
    assert_eq!(snapshot.app_hosts.len(), 1);
    assert_eq!(snapshot.builders.len(), 1);
}

#[test]
fn partial_cost_refresh_keeps_fresh_mtd_and_marks_reused_forecast_stale() {
    let make = |costs| {
        build_snapshot(
            database(Vec::new()),
            Ok(AccountIdentity {
                account: ACCOUNT.into(),
                principal: "admin".into(),
            }),
            Ok(InventorySnapshot {
                regions_scanned: 1,
                instance_regions_succeeded: 1,
                ..InventorySnapshot::default()
            }),
            costs,
            Utc::now(),
        )
    };
    let previous = make(CostSnapshot {
        mtd_micros: Some(10_000_000),
        forecast_micros: Some(20_000_000),
        currency: "USD".into(),
        ..CostSnapshot::default()
    });
    let next = make(CostSnapshot {
        mtd_micros: Some(30_000_000),
        currency: "USD".into(),
        issues: vec!["forecast unavailable: access denied".into()],
        ..CostSnapshot::default()
    });

    let merged = previous.merge_refresh(next);

    assert!(merged.costs.iter().any(|row| {
        row.kind == "MTD" && row.details.contains("USD 30.00") && !row.details.contains("stale")
    }));
    assert!(merged.costs.iter().any(|row| {
        row.kind == "FORECAST" && row.details.starts_with("warning · stale · USD 50.00")
    }));
}

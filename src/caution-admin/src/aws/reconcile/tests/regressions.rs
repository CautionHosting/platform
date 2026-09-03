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

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use drift_detector::drift::DriftSeverity;
use uuid::Uuid;

use super::{aws_snapshot, finding, resource, screen_text};
use crate::{
    aws::AwsSection,
    model::ResourceKind,
    state::{AppState, Row, Screen},
};

#[test]
fn empty_findings_are_stated_plainly() {
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(Vec::new()));
    state.open_aws_section(AwsSection::Findings);
    let text = screen_text(&mut state);
    assert!(text.contains("No findings"));
    assert!(!text.contains("No confirmed findings"));
}

#[test]
fn unavailable_inventory_is_not_presented_as_zero_findings() {
    let mut snapshot = aws_snapshot(Vec::new());
    snapshot.inventory_available = false;
    snapshot.inventory_complete = false;
    snapshot.metadata.status = "partial".to_string();
    let mut state = AppState::new();
    state.open_aws_overview(snapshot);
    state.open_aws_section(AwsSection::Findings);

    let text = screen_text(&mut state);
    assert!(text.contains("Findings: Unavailable"));
    assert!(text.contains("Coverage: Not scanned"));
    assert!(text.contains("AWS inventory was not scanned"));
    assert!(!text.contains("No findings"));
    assert!(!text.contains("0 critical"));
}

#[test]
fn refresh_does_not_preserve_a_status_by_matching_its_text() {
    let snapshot = aws_snapshot(Vec::new());
    let mut state = AppState::new();
    state.open_aws_overview(snapshot.clone());
    state.set_status("Finding cleared by refresh");

    state.replace_aws(snapshot);

    assert!(state.current.status.is_none());
}

#[test]
fn finding_identity_canonicalizes_linked_resources() {
    let mut app = resource(ResourceKind::App, "api").summary();
    app.id = Uuid::from_u128(1);
    let mut organization = resource(ResourceKind::Organization, "Acme").summary();
    organization.id = Uuid::from_u128(2);
    let first = finding(vec![app.clone(), organization.clone()]);
    let second = finding(vec![organization, app.clone(), app]);
    assert_eq!(first.key(), second.key());
}

#[test]
fn refresh_uses_resource_identity_instead_of_display_text() {
    let mut linked = resource(ResourceKind::App, "api").summary();
    linked.id = Uuid::from_u128(1);
    let item = finding(vec![linked]);
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![item.clone()]));
    state.open_aws_section(AwsSection::Findings);
    state.open_aws_finding(item.clone());

    let mut updated = item;
    updated.severity = DriftSeverity::Warning;
    updated.subject = "renamed api".to_string();
    updated.platform = "stopped · expected EC2 i-api".to_string();
    updated.aws = "stopped EC2 i-api".to_string();
    updated.resources[0].label = "renamed api".to_string();
    updated.resources[0].context = Some("stopped".to_string());
    state.replace_aws(aws_snapshot(vec![updated.clone()]));

    assert!(matches!(
        &state.current.screen,
        Screen::AwsFinding(current) if current == &updated
    ));
    assert!(state.current.status.is_none());
    assert!(
        state
            .current
            .rows
            .iter()
            .any(|row| matches!(row, Row::Resource(resource) if resource.label == "renamed api"))
    );
}

#[test]
fn list_selection_uses_stable_identity_and_missing_findings_clear() {
    let mut first_resource = resource(ResourceKind::App, "first").summary();
    first_resource.id = Uuid::from_u128(1);
    let mut second_resource = resource(ResourceKind::App, "second").summary();
    second_resource.id = Uuid::from_u128(2);
    let first = finding(vec![first_resource]);
    let mut second = finding(vec![second_resource]);
    second.subject = "second".to_string();

    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![first.clone(), second.clone()]));
    state.open_aws_section(AwsSection::Findings);
    state.current.selected = 1;

    let mut updated_first = first;
    updated_first.subject = "first renamed".to_string();
    updated_first.resources[0].label = "first renamed".to_string();
    let mut updated_second = second.clone();
    updated_second.subject = "second renamed".to_string();
    updated_second.resources[0].label = "second renamed".to_string();
    state.replace_aws(aws_snapshot(vec![updated_first, updated_second]));
    assert!(matches!(
        state.selected_row(),
        Some(Row::AwsFinding(selected)) if selected.resources[0].id == Uuid::from_u128(2)
    ));

    state.open_aws_finding(second);
    state.replace_aws(aws_snapshot(Vec::new()));
    assert!(matches!(
        state.current.screen,
        Screen::AwsSection(AwsSection::Findings)
    ));
    assert_eq!(
        state
            .current
            .status
            .as_ref()
            .map(|status| status.text.as_str()),
        Some("Finding cleared by refresh")
    );
}

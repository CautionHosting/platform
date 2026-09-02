// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{
    AwsAction, AwsDisplayRow,
    cost::{CostSnapshot, money},
    inventory::AwsInstance,
    resource_summary,
};
use crate::{
    db::{
        aws::{AwsAppRow, AwsBuildRow, AwsDatabaseState},
        billing_source, byoc_capacity, pending_change, status, tier_name,
    },
    model::ResourceKind,
};

pub(super) fn cost_rows(costs: &CostSnapshot) -> Vec<AwsDisplayRow> {
    let mut rows = Vec::new();
    if let Some(mtd) = costs.mtd_micros {
        rows.push(row(
            "MTD",
            "Month to date",
            format!(
                "active · {} · {}",
                money(mtd, &costs.currency),
                costs.period.as_deref().unwrap_or("current month")
            ),
        ));
    }
    if let (Some(mtd), Some(forecast)) = (costs.mtd_micros, costs.forecast_micros) {
        rows.push(row(
            "FORECAST",
            "Projected month end",
            format!("active · {}", money(mtd + forecast, &costs.currency)),
        ));
    } else if costs.first_day
        && let Some(forecast) = costs.forecast_micros
    {
        rows.push(row(
            "FORECAST",
            "Projected month end",
            format!("active · {}", money(forecast, &costs.currency)),
        ));
    }
    rows.extend(costs.services.iter().map(|line| {
        row(
            "SERVICE",
            &line.name,
            format!("active · {}", money(line.amount_micros, &line.currency)),
        )
    }));
    rows.extend(costs.attribution.iter().map(|line| {
        row(
            "TAG",
            &line.name,
            format!("active · {}", money(line.amount_micros, &line.currency)),
        )
    }));
    rows.extend(
        costs
            .issues
            .iter()
            .map(|issue| row("COST", "Unavailable", format!("warning · {issue}"))),
    );
    rows
}

pub(super) fn byoc_rows(database: &AwsDatabaseState) -> Vec<AwsDisplayRow> {
    database
        .byoc
        .iter()
        .map(|subscription| {
            let mut details = format!(
                "{} · subscription {} · {} · {} · {}",
                status(subscription.organization_active),
                subscription.status,
                tier_name(&subscription.tier),
                byoc_capacity(
                    subscription.allocated_apps,
                    Some(subscription.max_apps),
                    subscription.pending_max_apps,
                ),
                billing_source(&subscription.billing_source),
            );
            if subscription.pending_tier.is_some() || subscription.pending_max_apps.is_some() {
                details.push_str(" · pending ");
                details.push_str(&pending_change(
                    subscription.pending_tier.as_deref(),
                    subscription.pending_max_apps,
                ));
            }
            AwsDisplayRow {
                kind: "ORGANIZATION".to_string(),
                name: subscription.organization_name.clone(),
                details,
                action: AwsAction::Resource(resource_summary(
                    ResourceKind::Organization,
                    subscription.organization_id,
                    subscription.organization_name.clone(),
                )),
            }
        })
        .collect()
}

pub(super) fn host_row(instance: &AwsInstance, app: Option<&AwsAppRow>) -> AwsDisplayRow {
    let (name, details, action) = app.map_or_else(
        || {
            (
                instance.instance_id.clone(),
                format!(
                    "{} · AWS host · unlinked · {} · {}",
                    instance.state,
                    instance.instance_type.as_deref().unwrap_or("unknown type"),
                    instance.region,
                ),
                AwsAction::None,
            )
        },
        |app| {
            let details = if app.destroyed || app.state == "terminated" {
                format!(
                    "failed · AWS {} · Platform terminated · {} · {} · {}",
                    instance.state,
                    instance.instance_id,
                    instance.instance_type.as_deref().unwrap_or("unknown type"),
                    instance.region,
                )
            } else if app.state != instance.state {
                format!(
                    "warning · AWS {} · Platform {} · {} · {} · {}",
                    instance.state,
                    app.state,
                    instance.instance_id,
                    instance.instance_type.as_deref().unwrap_or("unknown type"),
                    instance.region,
                )
            } else {
                format!(
                    "{} · AWS host · Platform {} · {} · {} · {}",
                    instance.state,
                    app.state,
                    instance.instance_id,
                    instance.instance_type.as_deref().unwrap_or("unknown type"),
                    instance.region,
                )
            };
            (app.name.clone(), details, app_action(app))
        },
    );
    AwsDisplayRow {
        kind: "HOST".to_string(),
        name,
        details,
        action,
    }
}

pub(super) fn tagged_host_row(instance: &AwsInstance, app: &AwsAppRow) -> AwsDisplayRow {
    AwsDisplayRow {
        kind: "HOST".to_string(),
        name: instance.instance_id.clone(),
        details: format!(
            "{} · AWS {} · tagged app {} is {} · DB host {}",
            if app.destroyed || app.state == "terminated" {
                "failed"
            } else {
                "warning"
            },
            instance.state,
            app.name,
            app.state,
            app.provider_resource_id,
        ),
        action: AwsAction::None,
    }
}

pub(super) fn builder_row(instance: &AwsInstance, build: Option<&AwsBuildRow>) -> AwsDisplayRow {
    AwsDisplayRow {
        kind: "BUILDER".to_string(),
        name: build.map_or_else(
            || instance.instance_id.clone(),
            |build| format!("build {}", build.id),
        ),
        details: format!(
            "{} · {} · {}",
            instance.state, instance.instance_id, instance.region
        ),
        action: build.map(build_action).unwrap_or(AwsAction::None),
    }
}

pub(super) fn app_action(app: &AwsAppRow) -> AwsAction {
    AwsAction::Resource(resource_summary(
        ResourceKind::App,
        app.id,
        app.name.clone(),
    ))
}

pub(super) fn build_action(build: &AwsBuildRow) -> AwsAction {
    if let Some(app_id) = build.app_id {
        AwsAction::Resource(resource_summary(
            ResourceKind::App,
            app_id,
            build
                .app_name
                .clone()
                .unwrap_or_else(|| "(unnamed app)".to_string()),
        ))
    } else {
        AwsAction::Resource(resource_summary(
            ResourceKind::Organization,
            build.organization_id,
            build.organization_name.clone(),
        ))
    }
}

fn row(kind: &str, name: &str, details: String) -> AwsDisplayRow {
    AwsDisplayRow {
        kind: kind.to_string(),
        name: name.to_string(),
        details,
        action: AwsAction::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::aws::ByocSubscriptionRow;
    use uuid::Uuid;

    #[test]
    fn first_day_forecast_is_still_a_month_end_projection() {
        let rows = cost_rows(&CostSnapshot {
            forecast_micros: Some(12_340_000),
            currency: "USD".to_string(),
            first_day: true,
            ..CostSnapshot::default()
        });
        assert!(
            rows.iter()
                .any(|row| { row.kind == "FORECAST" && row.details == "active · USD 12.34" })
        );
        assert!(!rows.iter().any(|row| row.kind == "MTD"));
    }

    #[test]
    fn byoc_rows_use_organization_status_and_subscription_details() {
        let organization_id = Uuid::new_v4();
        let rows = byoc_rows(&AwsDatabaseState {
            apps: Vec::new(),
            builds: Vec::new(),
            byoc: vec![ByocSubscriptionRow {
                organization_id,
                organization_name: "Acme".to_string(),
                organization_active: true,
                tier: "growth".to_string(),
                status: "active".to_string(),
                billing_source: "paddle".to_string(),
                max_apps: 5,
                pending_tier: Some("scale".to_string()),
                pending_max_apps: Some(3),
                allocated_apps: 2,
            }],
        });

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "ORGANIZATION");
        assert_eq!(rows[0].name, "Acme");
        assert_eq!(
            rows[0].details,
            "active · subscription active · Growth · 2 / 3 used · Paddle · pending Scale · 3 apps"
        );
        assert!(matches!(
            &rows[0].action,
            AwsAction::Resource(resource)
                if resource.kind == ResourceKind::Organization && resource.id == organization_id
        ));
    }
}

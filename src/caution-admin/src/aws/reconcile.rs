// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use drift_detector::drift::{DriftSeverity, classify_caution_resource};

use super::{
    AccountIdentity, AwsAction, AwsDisplayRow, AwsFinding, AwsOverviewMetadata, AwsSection,
    AwsSnapshot,
    cost::{CostRetention, CostSnapshot},
    display::{byoc_rows, cost_rows},
    inventory::{FetchInventoryError, InventorySnapshot},
    is_cost_summary,
};
use crate::db::aws::AwsDatabaseState;

mod findings;

pub(crate) fn build_snapshot(
    database: AwsDatabaseState,
    identity: Result<AccountIdentity, super::FetchIdentityError>,
    inventory: Result<InventorySnapshot, FetchInventoryError>,
    costs: CostSnapshot,
    updated_at: DateTime<Utc>,
) -> AwsSnapshot {
    let updated_at = updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let identity_available = identity.is_ok();
    let (account, principal) = match identity {
        Ok(identity) => (identity.account, identity.principal),
        Err(error) => ("Unavailable".to_string(), unavailable_reason(&error)),
    };
    let inventory_loaded = inventory.is_ok();
    let (inventory, regions) = match inventory {
        Ok(inventory) => {
            let regions = format!(
                "{} scanned · {} with resources · {} partial failures",
                inventory.regions_scanned,
                inventory.regions_with_resources,
                inventory.issues.len()
            );
            (inventory, regions)
        }
        Err(error) => (InventorySnapshot::default(), unavailable_reason(&error)),
    };
    let inventory_complete = inventory_loaded && inventory.issues.is_empty();
    let instances_available = inventory_loaded && inventory.instance_regions_succeeded > 0;
    let instances_complete =
        instances_available && inventory.instance_regions_succeeded == inventory.regions_scanned;
    let storage_complete = inventory_loaded
        && component_complete(&inventory, "volumes")
        && component_complete(&inventory, "public IPs")
        && instances_complete;
    let Reconciled {
        app_hosts,
        builders,
        hosts,
        storage,
        findings,
        unrelated_instances,
        storage_gib,
        unassociated_ips,
    } = if inventory_loaded {
        let findings = findings::reconcile_inventory(
            &database,
            &inventory,
            identity_available.then_some(account.as_str()),
        );
        let (storage, storage_gib, unassociated_ips) =
            storage_rows(&inventory, &findings.caution_instances);
        Reconciled {
            app_hosts: findings.app_hosts,
            builders: findings.builders,
            hosts: findings.hosts,
            storage,
            findings: findings.findings,
            unrelated_instances: findings.unrelated_instances,
            storage_gib,
            unassociated_ips,
        }
    } else {
        unavailable_inventory()
    };
    let cost_rows = cost_rows(&costs);
    let costs_available = costs_available(&costs);
    let byoc = byoc_rows(&database);
    let projected = projected_cost(&costs);
    let overview = overview_rows(
        &app_hosts,
        &builders,
        &storage,
        &findings,
        &cost_rows,
        &byoc,
        OverviewQuality {
            inventory_loaded,
            instances_available,
            instances_complete,
            storage_complete,
            costs_available,
        },
        unrelated_instances,
        storage_gib,
        unassociated_ips,
        &projected,
    );
    let status =
        if identity_available && instances_available && inventory_complete && costs_available {
            "complete"
        } else {
            "partial"
        };

    AwsSnapshot {
        metadata: AwsOverviewMetadata {
            account,
            principal,
            regions,
            updated: format!("{updated_at} · r refresh"),
            status: status.to_string(),
        },
        overview,
        app_hosts,
        builders,
        hosts,
        storage,
        findings,
        costs: cost_rows,
        cost_snapshot: costs,
        byoc,
        stale_reason: None,
        identity_available,
        inventory_available: inventory_loaded,
        inventory_complete,
        instances_available,
        instances_complete,
        costs_available,
    }
}

pub(super) fn replace_costs(
    snapshot: &mut AwsSnapshot,
    costs: CostSnapshot,
    retained: CostRetention,
) {
    let costs_available = costs_available(&costs);
    let mut rows = cost_rows(&costs);
    for row in &mut rows {
        let stale = match row.kind.as_str() {
            "MTD" | "SERVICE" => retained.primary,
            "FORECAST" => retained.forecast,
            "MANAGED BY" => retained.managed_by,
            "ORG TAG" => retained.organizations,
            _ => false,
        };
        if stale {
            row.details = format!("warning · stale · {}", strip_status(&row.details));
        }
    }
    let projected = projected_cost(&costs);
    let row = cost_overview_row(&rows, costs_available, &projected);
    if let Some(current) = snapshot
        .overview
        .iter_mut()
        .find(|current| current.action == AwsAction::Section(AwsSection::Costs))
    {
        *current = row;
    }
    snapshot.costs = rows;
    snapshot.costs_available = costs_available;
    snapshot.cost_snapshot = costs;
}

fn strip_status(details: &str) -> &str {
    details.split_once(" · ").map_or(details, |(_, rest)| rest)
}

fn costs_available(costs: &CostSnapshot) -> bool {
    costs.primary_available()
        && costs
            .issues
            .iter()
            .all(|issue| !issue.contains("unavailable:"))
}

fn projected_cost(costs: &CostSnapshot) -> String {
    match (costs.mtd_micros, costs.forecast_micros) {
        (Some(mtd), Some(forecast)) => super::cost::money(mtd + forecast, &costs.currency),
        (None, Some(forecast)) if costs.first_day => super::cost::money(forecast, &costs.currency),
        _ => "unavailable".to_string(),
    }
}

struct OverviewQuality {
    inventory_loaded: bool,
    instances_available: bool,
    instances_complete: bool,
    storage_complete: bool,
    costs_available: bool,
}

#[allow(clippy::too_many_arguments)]
fn overview_rows(
    app_hosts: &[AwsDisplayRow],
    builders: &[AwsDisplayRow],
    storage: &[AwsDisplayRow],
    findings: &[AwsFinding],
    costs: &[AwsDisplayRow],
    byoc: &[AwsDisplayRow],
    quality: OverviewQuality,
    unrelated_instances: usize,
    storage_gib: i64,
    unassociated_ips: usize,
    projected: &str,
) -> Vec<AwsDisplayRow> {
    let critical = findings
        .iter()
        .filter(|finding| finding.severity == DriftSeverity::Critical)
        .count();
    let warning = findings.len() - critical;
    let findings_name = if !quality.instances_available {
        "Findings (?)".to_string()
    } else if quality.instances_complete {
        format!("Findings ({})", findings.len())
    } else {
        format!("Findings ({}+)", findings.len())
    };
    vec![
        section_row(
            AwsSection::AppHosts,
            count_name(
                AwsSection::AppHosts,
                app_hosts.len(),
                quality.instances_complete,
            ),
            inventory_details(
                quality.instances_available,
                quality.instances_complete,
                format!("{unrelated_instances} unrelated EC2 instances"),
            ),
        ),
        section_row(
            AwsSection::Builders,
            count_name(
                AwsSection::Builders,
                builders.len(),
                quality.instances_complete,
            ),
            inventory_details(
                quality.instances_available,
                quality.instances_complete,
                "live AWS hosts".to_string(),
            ),
        ),
        section_row(
            AwsSection::Storage,
            count_name(AwsSection::Storage, storage.len(), quality.storage_complete),
            inventory_details(
                quality.inventory_loaded,
                quality.storage_complete,
                format!("{storage_gib} GiB EBS · {unassociated_ips} unassociated IPs"),
            ),
        ),
        section_row(
            AwsSection::Findings,
            findings_name,
            if !quality.instances_available {
                "warning · inventory unavailable".to_string()
            } else if findings.is_empty() && quality.instances_complete {
                "clear · no confirmed findings".to_string()
            } else {
                format!(
                    "{} · {critical} critical · {warning} warning{}",
                    if critical > 0 { "failed" } else { "warning" },
                    if quality.instances_complete {
                        ""
                    } else {
                        " · partial scan"
                    }
                )
            },
        ),
        cost_overview_row(costs, quality.costs_available, projected),
        section_row(
            AwsSection::Byoc,
            format!("BYOC ({})", byoc.len()),
            "active · Platform subscriptions only; customer AWS not queried".to_string(),
        ),
    ]
}

fn cost_overview_row(costs: &[AwsDisplayRow], available: bool, projected: &str) -> AwsDisplayRow {
    section_row(
        AwsSection::Costs,
        if available {
            format!(
                "Costs ({})",
                costs.iter().filter(|row| !is_cost_summary(row)).count()
            )
        } else {
            "Costs (?)".to_string()
        },
        format!(
            "{} · projected {projected}",
            if available { "active" } else { "warning" }
        ),
    )
}

fn count_name(section: AwsSection, count: usize, complete: bool) -> String {
    if complete {
        format!("{} ({count})", section.label())
    } else {
        format!("{} (?)", section.label())
    }
}

fn inventory_details(loaded: bool, complete: bool, details: String) -> String {
    if !loaded {
        "warning · inventory unavailable".to_string()
    } else if !complete {
        "warning · partial regional inventory".to_string()
    } else {
        format!("active · {details}")
    }
}

fn section_row(section: AwsSection, name: String, details: String) -> AwsDisplayRow {
    row("AWS", name, details, AwsAction::Section(section))
}

fn component_complete(inventory: &InventorySnapshot, component: &str) -> bool {
    inventory
        .issues
        .iter()
        .all(|issue| issue.component != component)
}

fn unavailable_inventory() -> Reconciled {
    Reconciled {
        app_hosts: Vec::new(),
        builders: Vec::new(),
        hosts: Vec::new(),
        storage: Vec::new(),
        findings: Vec::new(),
        unrelated_instances: 0,
        storage_gib: 0,
        unassociated_ips: 0,
    }
}

struct Reconciled {
    app_hosts: Vec<AwsDisplayRow>,
    builders: Vec<AwsDisplayRow>,
    hosts: Vec<super::AwsHost>,
    storage: Vec<AwsDisplayRow>,
    findings: Vec<AwsFinding>,
    unrelated_instances: usize,
    storage_gib: i64,
    unassociated_ips: usize,
}

fn storage_rows(
    inventory: &InventorySnapshot,
    caution_instances: &HashSet<String>,
) -> (Vec<AwsDisplayRow>, i64, usize) {
    let mut rows = Vec::new();
    let mut total_gib = 0_i64;
    let mut unassociated_ips = 0;
    for volume in &inventory.volumes {
        let managed = classify_caution_resource(&volume.tags).is_some()
            || volume
                .attached_instances
                .iter()
                .any(|id| caution_instances.contains(id));
        if managed {
            total_gib += i64::from(volume.size_gib);
            rows.push(row(
                "EBS",
                volume.volume_id.clone(),
                format!(
                    "{} · {} GiB · {} · {}",
                    if volume.attached_instances.is_empty() {
                        "warning"
                    } else {
                        "active"
                    },
                    volume.size_gib,
                    volume.state,
                    volume.region
                ),
                AwsAction::None,
            ));
        }
    }
    for address in &inventory.addresses {
        let managed = classify_caution_resource(&address.tags).is_some()
            || address
                .instance_id
                .as_deref()
                .is_some_and(|id| caution_instances.contains(id));
        if managed {
            if address.instance_id.is_none() {
                unassociated_ips += 1;
            }
            rows.push(row(
                "IPV4",
                address.public_ip.clone(),
                format!(
                    "{} · {} · {}",
                    if address.instance_id.is_some() {
                        "active"
                    } else {
                        "failed"
                    },
                    address.instance_id.as_deref().unwrap_or("unassociated"),
                    address.region
                ),
                AwsAction::None,
            ));
        }
    }
    (rows, total_gib, unassociated_ips)
}

fn row(
    kind: impl Into<String>,
    name: impl Into<String>,
    details: String,
    action: AwsAction,
) -> AwsDisplayRow {
    AwsDisplayRow {
        kind: kind.into(),
        name: name.into(),
        details,
        action,
    }
}

fn unavailable_reason(error: &dyn std::error::Error) -> String {
    if super::inventory::error_chain_contains(error, "accessdenied") {
        "access denied"
    } else if error.to_string().contains("timed out") {
        "timed out"
    } else {
        "unavailable"
    }
    .to_string()
}

#[cfg(test)]
mod tests;

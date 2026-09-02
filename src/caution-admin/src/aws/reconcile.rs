// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::{HashMap, HashSet};

use super::{
    AccountIdentity, AwsAction, AwsDisplayRow, AwsOverviewMetadata, AwsSection, AwsSnapshot,
    cost::{CostSnapshot, money},
    display::{
        app_action, build_action, builder_row, byoc_rows, cost_rows, host_row, tagged_host_row,
    },
    inventory::{FetchInventoryError, InventorySnapshot},
};
use crate::db::aws::{AwsAppRow, AwsBuildRow, AwsDatabaseState};
use chrono::{DateTime, Utc};
use drift_detector::drift::{CautionResourceKind, classify_caution_resource};

pub(crate) fn build_snapshot(
    database: AwsDatabaseState,
    identity: Result<AccountIdentity, super::FetchIdentityError>,
    inventory: Result<InventorySnapshot, FetchInventoryError>,
    costs: CostSnapshot,
    updated_at: DateTime<Utc>,
) -> AwsSnapshot {
    let updated_at = updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut overview = Vec::new();
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
    let inventory_available = inventory_loaded && inventory.issues.is_empty();

    let Reconciled {
        app_hosts,
        builders,
        storage,
        drift,
        unrelated_instances,
        storage_gib,
        unassociated_ips,
    } = if inventory_loaded {
        reconcile_inventory(&database, &inventory)
    } else {
        unavailable_inventory()
    };
    let instances_complete = inventory_loaded && component_complete(&inventory, "instances");
    let storage_complete = inventory_loaded
        && component_complete(&inventory, "volumes")
        && component_complete(&inventory, "public IPs");
    let cost_rows = cost_rows(&costs);
    let costs_available = (costs.mtd_micros.is_some() || costs.first_day)
        && costs
            .issues
            .iter()
            .all(|issue| !issue.contains("unavailable:"));
    let byoc = byoc_rows(&database);
    let projected = match (costs.mtd_micros, costs.forecast_micros) {
        (Some(mtd), Some(forecast)) => money(mtd + forecast, &costs.currency),
        (None, Some(forecast)) if costs.first_day => money(forecast, &costs.currency),
        _ => "unavailable".to_string(),
    };
    for (section, count, details) in [
        (
            AwsSection::AppHosts,
            instances_complete.then_some(app_hosts.len()),
            if instances_complete {
                format!("active · {unrelated_instances} unrelated EC2 instances")
            } else if inventory_loaded {
                "warning · partial regional inventory".to_string()
            } else {
                "warning · inventory unavailable".to_string()
            },
        ),
        (
            AwsSection::Builders,
            instances_complete.then_some(builders.len()),
            if instances_complete {
                "active · live AWS hosts"
            } else if inventory_loaded {
                "warning · partial regional inventory"
            } else {
                "warning · inventory unavailable"
            }
            .to_string(),
        ),
        (
            AwsSection::Storage,
            storage_complete.then_some(storage.len()),
            if storage_complete {
                format!("active · {storage_gib} GiB EBS · {unassociated_ips} unassociated IPs")
            } else if inventory_loaded {
                format!("warning · partial · observed {storage_gib} GiB EBS")
            } else {
                "warning · inventory unavailable".to_string()
            },
        ),
        (
            AwsSection::Drift,
            instances_complete.then_some(drift.len()),
            if !inventory_loaded {
                "warning · inventory unavailable"
            } else if !instances_complete {
                "warning · partial regional inventory"
            } else if drift.is_empty() {
                "clear · no findings"
            } else {
                "warning · review findings"
            }
            .to_string(),
        ),
        (
            AwsSection::Costs,
            costs_available.then_some(cost_rows.len()),
            format!(
                "{} · projected {projected}",
                if costs.forecast_micros.is_some()
                    && (costs.mtd_micros.is_some() || costs.first_day)
                {
                    "active"
                } else {
                    "warning"
                }
            ),
        ),
        (
            AwsSection::Byoc,
            Some(byoc.len()),
            "active · Platform subscriptions only; customer AWS not queried".to_string(),
        ),
    ] {
        overview.push(row(
            "AWS",
            count.map_or_else(
                || format!("{} (?)", section.label()),
                |count| format!("{} ({count})", section.label()),
            ),
            details,
            AwsAction::Section(section),
        ));
    }

    AwsSnapshot {
        metadata: AwsOverviewMetadata {
            account,
            principal,
            regions,
            updated: format!("{updated_at} · r refresh"),
            status: if identity_available && inventory_available {
                "active"
            } else {
                "warning"
            }
            .to_string(),
        },
        overview,
        app_hosts,
        builders,
        storage,
        drift,
        costs: cost_rows,
        byoc,
        stale_reason: None,
        identity_available,
        inventory_available,
        costs_available,
    }
}

fn component_complete(inventory: &InventorySnapshot, component: &str) -> bool {
    inventory
        .issues
        .iter()
        .all(|issue| issue.component != component)
}

fn unavailable_inventory() -> Reconciled {
    let unavailable = |kind: &str, name: &str| {
        vec![row(
            kind,
            name,
            "warning · unavailable; region discovery failed".to_string(),
            AwsAction::None,
        )]
    };
    Reconciled {
        app_hosts: unavailable("HOST", "Unavailable"),
        builders: unavailable("BUILDER", "Unavailable"),
        storage: unavailable("STORAGE", "Unavailable"),
        drift: unavailable("DRIFT", "Unavailable"),
        unrelated_instances: 0,
        storage_gib: 0,
        unassociated_ips: 0,
    }
}

struct Reconciled {
    app_hosts: Vec<AwsDisplayRow>,
    builders: Vec<AwsDisplayRow>,
    storage: Vec<AwsDisplayRow>,
    drift: Vec<AwsDisplayRow>,
    unrelated_instances: usize,
    storage_gib: i64,
    unassociated_ips: usize,
}

fn reconcile_inventory(database: &AwsDatabaseState, inventory: &InventorySnapshot) -> Reconciled {
    let apps_by_id: HashMap<String, &AwsAppRow> = database
        .apps
        .iter()
        .map(|app| (app.id.to_string(), app))
        .collect();
    let apps_by_instance: HashMap<&str, &AwsAppRow> = database
        .apps
        .iter()
        .map(|app| (app.provider_resource_id.as_str(), app))
        .collect();
    let builds_by_id: HashMap<String, &AwsBuildRow> = database
        .builds
        .iter()
        .map(|build| (build.id.to_string(), build))
        .collect();
    let builds_by_instance: HashMap<&str, &AwsBuildRow> = database
        .builds
        .iter()
        .filter_map(|build| Some((build.builder_instance_id.as_deref()?, build)))
        .fold(HashMap::new(), |mut builds, (instance_id, build)| {
            builds.entry(instance_id).or_insert(build);
            builds
        });
    let mut matched_apps = HashSet::new();
    let mut linked_apps = HashSet::new();
    let mut caution_instances = HashSet::new();
    let mut app_hosts = Vec::new();
    let mut builders = Vec::new();
    let mut drift = Vec::new();
    let mut unrelated_instances = 0;
    let failed_instance_regions = inventory
        .issues
        .iter()
        .filter(|issue| issue.component == "instances")
        .filter_map(|issue| issue.region.as_deref())
        .collect::<HashSet<_>>();

    for instance in &inventory.instances {
        match classify_caution_resource(&instance.tags) {
            Some(CautionResourceKind::Deployment) => {
                caution_instances.insert(instance.instance_id.as_str());
                let resource_id = tag(&instance.tags, &["ResourceId", "caution:resource_id"]);
                let tagged_app = resource_id.and_then(|id| apps_by_id.get(id).copied());
                let exact_app = apps_by_instance.get(instance.instance_id.as_str()).copied();
                if let Some(app) = exact_app {
                    matched_apps.insert(app.id);
                    let first_match = linked_apps.insert(app.id);
                    app_hosts.push(host_row(instance, Some(app)));
                    if !first_match {
                        drift.push(drift_row(
                            "DUPLICATE",
                            &app.name,
                            format!("failed · multiple AWS hosts · {}", instance.instance_id),
                            Some(app),
                        ));
                    }
                    if let Some(tagged_app) = tagged_app.filter(|tagged| tagged.id != app.id) {
                        drift.push(drift_row(
                            "LINK",
                            &instance.instance_id,
                            format!(
                                "failed · AWS host belongs to {} · tag points to {}",
                                app.name, tagged_app.name
                            ),
                            Some(tagged_app),
                        ));
                    }
                    if app.destroyed || app.state == "terminated" {
                        drift.push(drift_row(
                            "ORPHAN",
                            &app.name,
                            format!(
                                "failed · AWS {} · Platform terminated · {}",
                                instance.state, instance.instance_id,
                            ),
                            Some(app),
                        ));
                    } else if app.state != instance.state {
                        drift.push(drift_row(
                            "STATE",
                            &app.name,
                            format!("warning · AWS {} · Platform {}", instance.state, app.state),
                            Some(app),
                        ));
                    }
                } else if let Some(app) = tagged_app {
                    let first_match = linked_apps.insert(app.id);
                    app_hosts.push(tagged_host_row(instance, app));
                    drift.push(drift_row(
                        "LINK",
                        &instance.instance_id,
                        format!(
                            "{} · AWS {} · tagged for {} · DB host {}",
                            if app.destroyed || app.state == "terminated" {
                                "failed"
                            } else {
                                "warning"
                            },
                            instance.state,
                            app.name,
                            app.provider_resource_id,
                        ),
                        Some(app),
                    ));
                    if !first_match {
                        drift.push(drift_row(
                            "DUPLICATE",
                            &app.name,
                            format!("failed · multiple AWS hosts · {}", instance.instance_id),
                            Some(app),
                        ));
                    }
                } else {
                    app_hosts.push(host_row(instance, None));
                    drift.push(row(
                        "UNKNOWN",
                        instance.instance_id.clone(),
                        format!(
                            "failed · Caution-tagged host in {} has no Platform app",
                            instance.region
                        ),
                        AwsAction::None,
                    ));
                }
            }
            Some(CautionResourceKind::Builder) => {
                caution_instances.insert(instance.instance_id.as_str());
                let build = instance
                    .tags
                    .get("BuildId")
                    .and_then(|id| builds_by_id.get(id).copied())
                    .or_else(|| {
                        builds_by_instance
                            .get(instance.instance_id.as_str())
                            .copied()
                    });
                builders.push(builder_row(instance, build));
                if build.is_none_or(|build| {
                    !matches!(build.status.as_str(), "pending" | "building" | "uploading")
                }) {
                    drift.push(row(
                        "BUILDER",
                        instance.instance_id.clone(),
                        match build {
                            Some(build) => format!(
                                "warning · live host for {} build {}",
                                build.status, build.id
                            ),
                            None => "warning · live host has no tracked build".to_string(),
                        },
                        build.map(build_action).unwrap_or(AwsAction::None),
                    ));
                }
            }
            None => unrelated_instances += 1,
        }
    }
    for app in database
        .apps
        .iter()
        .filter(|app| !app.managed_on_prem && !app.destroyed && app.state != "terminated")
        .filter(|app| match app.region.as_deref() {
            Some(region) => !failed_instance_regions.contains(region),
            None => failed_instance_regions.is_empty(),
        })
        .filter(|app| !matched_apps.contains(&app.id))
    {
        drift.push(drift_row(
            "MISSING",
            &app.name,
            format!("failed · DB {} · no AWS host", app.state),
            Some(app),
        ));
    }
    for issue in &inventory.issues {
        drift.push(row(
            "PARTIAL",
            issue.component,
            format!(
                "warning · {} · {}",
                issue.region.as_deref().unwrap_or("account"),
                issue.reason
            ),
            AwsAction::None,
        ));
    }
    let (storage, storage_gib, unassociated_ips) = storage_rows(inventory, &caution_instances);
    Reconciled {
        app_hosts,
        builders,
        storage,
        drift,
        unrelated_instances,
        storage_gib,
        unassociated_ips,
    }
}

fn storage_rows(
    inventory: &InventorySnapshot,
    caution_instances: &HashSet<&str>,
) -> (Vec<AwsDisplayRow>, i64, usize) {
    let mut rows = Vec::new();
    let mut total_gib = 0_i64;
    let mut unassociated_ips = 0;
    for volume in &inventory.volumes {
        let managed = classify_caution_resource(&volume.tags).is_some()
            || volume
                .attached_instances
                .iter()
                .any(|id| caution_instances.contains(id.as_str()));
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

fn drift_row(kind: &str, name: &str, details: String, app: Option<&AwsAppRow>) -> AwsDisplayRow {
    row(
        kind,
        name,
        details,
        app.map(app_action).unwrap_or(AwsAction::None),
    )
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

fn tag<'a>(tags: &'a HashMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| tags.get(*name).map(String::as_str))
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

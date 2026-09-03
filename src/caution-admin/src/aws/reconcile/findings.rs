// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::{HashMap, HashSet};

use drift_detector::drift::{CautionResourceKind, DriftSeverity, classify_caution_resource};

use crate::{
    aws::{
        AwsFinding, AwsHost, AwsHostPlatform, FindingKind,
        display::{app_summary, host_row, tagged_host_row},
        inventory::{AwsInstance, InventorySnapshot},
    },
    db::aws::{AwsAppRow, AwsBuildRow, AwsDatabaseState},
    model::ResourceSummary,
};

use super::{map_apps, map_builds};

mod builders;

pub(super) struct FindingResults {
    pub app_hosts: Vec<crate::aws::AwsDisplayRow>,
    pub builders: Vec<crate::aws::AwsDisplayRow>,
    pub hosts: Vec<AwsHost>,
    pub findings: Vec<AwsFinding>,
    pub caution_instances: HashSet<String>,
    pub unrelated_instances: usize,
}

enum AppScope {
    InScope,
    Invalid,
    Other {
        expected: String,
        observed: String,
    },
    Byoc {
        expected: String,
        observed: Option<String>,
    },
    IdentityUnavailable,
}

pub(super) fn reconcile_inventory(
    database: &AwsDatabaseState,
    inventory: &InventorySnapshot,
    account: Option<&str>,
) -> FindingResults {
    let apps_by_id = map_apps(&database.apps, |app| Some(app.id.to_string()));
    let apps_by_instance = map_apps(&database.apps, |app| {
        (!app.provider_resource_id.is_empty()).then(|| app.provider_resource_id.clone())
    });
    let builds_by_id = map_builds(&database.builds, |build| Some(build.id.to_string()));
    let builds_by_instance =
        map_builds(&database.builds, |build| build.builder_instance_id.clone());
    let failed_regions = inventory
        .issues
        .iter()
        .filter(|issue| issue.component == "instances")
        .filter_map(|issue| issue.region.as_deref())
        .collect::<HashSet<_>>();
    let mut result = FindingResults {
        app_hosts: Vec::new(),
        builders: Vec::new(),
        hosts: Vec::new(),
        findings: Vec::new(),
        caution_instances: HashSet::new(),
        unrelated_instances: 0,
    };
    let mut matched_expected = HashSet::new();
    let mut observed_apps = HashSet::new();
    let mut tagged_expected: HashMap<uuid::Uuid, Vec<&AwsInstance>> = HashMap::new();

    for instance in &inventory.instances {
        let exact_app = apps_by_instance.get(&instance.instance_id).copied();
        let exact_build = builds_by_instance.get(&instance.instance_id).copied();
        let classified = classify_caution_resource(&instance.tags);
        if let Some(app) = exact_app {
            mark_caution(instance, &mut result);
            observed_apps.insert(app.id);
            if matches!(app_scope(app, account), AppScope::InScope) {
                matched_expected.insert(app.id);
            }
            add_app_host(instance, app, "exact instance ID", account, &mut result);
            reconcile_exact_app(instance, app, classified, account, &apps_by_id, &mut result);
        } else if let Some(build) = exact_build {
            mark_caution(instance, &mut result);
            builders::add_build_host(instance, build, account, &mut result);
            builders::reconcile_exact_build(
                instance,
                build,
                classified,
                &builds_by_id,
                &mut result.findings,
            );
        } else {
            reconcile_tag_only(
                instance,
                classified,
                account,
                &apps_by_id,
                &builds_by_id,
                &mut tagged_expected,
                &mut observed_apps,
                &mut result,
            );
        }
    }

    let mut reported_tagged = HashSet::new();
    for app in database.apps.iter().filter(|app| {
        matches!(app_scope(app, account), AppScope::InScope)
            && matches!(app.state.as_str(), "running" | "stopped")
            && region_complete(app.region.as_deref(), &failed_regions)
            && !matched_expected.contains(&app.id)
    }) {
        let tagged = tagged_expected.get(&app.id).and_then(|items| items.first());
        if tagged.is_some() {
            reported_tagged.insert(app.id);
        }
        result.findings.push(AwsFinding {
            severity: if app.state == "running" {
                DriftSeverity::Critical
            } else {
                DriftSeverity::Warning
            },
            kind: FindingKind::ExpectedHostAbsent,
            subject: app.name.clone(),
            platform: format!("{} · expected EC2 {}", app.state, app.provider_resource_id),
            aws: tagged.map_or_else(
                || "expected EC2 absent from complete region scan".to_string(),
                |instance| {
                    format!(
                        "{} EC2 {} carries this app tag; expected EC2 absent",
                        instance.state, instance.instance_id
                    )
                },
            ),
            scope: tagged.map(|_| "ResourceId tag disagrees with Platform host ID".to_string()),
            host_id: tagged.map(|instance| instance.instance_id.clone()),
            resources: vec![app_summary(app)],
        });
    }
    for (app_id, instances) in tagged_expected {
        if reported_tagged.contains(&app_id) {
            continue;
        }
        let Some(app) = apps_by_id.get(&app_id.to_string()).copied() else {
            continue;
        };
        let Some(instance) = instances.first() else {
            continue;
        };
        let mut item = link_finding(instance, app);
        if instances.len() > 1 {
            item.scope = Some(format!(
                "{} EC2 hosts carry this ResourceId; Platform expects one different host",
                instances.len()
            ));
        }
        result.findings.push(item);
    }
    for app in database.apps.iter().filter(|app| {
        !app.managed_on_prem
            && !valid_account_id(&app.aws_account_id)
            && !observed_apps.contains(&app.id)
    }) {
        result.findings.push(AwsFinding {
            severity: DriftSeverity::Warning,
            kind: FindingKind::InvalidAccountMapping,
            subject: app.name.clone(),
            platform: format!("{} · provider account {}", app.state, app.aws_account_id),
            aws: "not evaluated until the provider account mapping is valid".to_string(),
            scope: Some("provider account is not a 12-digit AWS account ID".to_string()),
            host_id: None,
            resources: vec![app_summary(app)],
        });
    }
    sort_findings(&mut result.findings);
    result
}

fn app_scope(app: &AwsAppRow, account: Option<&str>) -> AppScope {
    if app.managed_on_prem {
        AppScope::Byoc {
            expected: app.aws_account_id.clone(),
            observed: account.map(str::to_string),
        }
    } else if !valid_account_id(&app.aws_account_id) {
        AppScope::Invalid
    } else if let Some(account) = account {
        if app.aws_account_id == account {
            AppScope::InScope
        } else {
            AppScope::Other {
                expected: app.aws_account_id.clone(),
                observed: account.to_string(),
            }
        }
    } else {
        AppScope::IdentityUnavailable
    }
}

fn valid_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn reconcile_exact_app(
    instance: &AwsInstance,
    app: &AwsAppRow,
    classified: Option<CautionResourceKind>,
    account: Option<&str>,
    apps_by_id: &HashMap<String, &AwsAppRow>,
    result: &mut FindingResults,
) {
    let mut item = combined_app_finding(instance, app, app_scope(app, account));
    let tagged_id = tag(&instance.tags, &["ResourceId", "caution:resource_id"]);
    let app_id = app.id.to_string();
    let bad_tag = classified == Some(CautionResourceKind::Builder)
        || tagged_id.is_some_and(|id| id != app_id);
    if bad_tag {
        let scope = tagged_id.map_or_else(
            || "AWS tags classify the exact app host as a builder".to_string(),
            |id| format!("AWS ResourceId tag points to {id}"),
        );
        if let Some(existing) = item.as_mut() {
            append_scope(existing, scope);
            if let Some(tagged) = tagged_id.and_then(|id| apps_by_id.get(id).copied()) {
                push_resource(&mut existing.resources, app_summary(tagged));
            }
        } else {
            let mut resources = vec![app_summary(app)];
            if let Some(tagged) = tagged_id.and_then(|id| apps_by_id.get(id).copied()) {
                push_resource(&mut resources, app_summary(tagged));
            }
            item = Some(AwsFinding {
                severity: DriftSeverity::Warning,
                kind: FindingKind::LinkMismatch,
                subject: instance.instance_id.clone(),
                platform: format!("{} owns exact EC2 ID", app.name),
                aws: format!("{} EC2 {}", instance.state, instance.instance_id),
                scope: Some(scope),
                host_id: Some(instance.instance_id.clone()),
                resources,
            });
        }
    }
    if let Some(item) = item {
        result.findings.push(item);
    }
}

fn combined_app_finding(
    instance: &AwsInstance,
    app: &AwsAppRow,
    scope: AppScope,
) -> Option<AwsFinding> {
    let scope = scope_finding(instance, app, scope);
    let lifecycle = lifecycle_finding(instance, app);
    match (scope, lifecycle) {
        (Some(mut scope), Some(mut lifecycle)) if lifecycle.severity == DriftSeverity::Critical => {
            lifecycle.scope = scope.scope.take();
            Some(lifecycle)
        }
        (Some(scope), _) => Some(scope),
        (None, lifecycle) => lifecycle,
    }
}

fn scope_finding(instance: &AwsInstance, app: &AwsAppRow, scope: AppScope) -> Option<AwsFinding> {
    let (kind, scope) = match scope {
        AppScope::Invalid => (
            FindingKind::InvalidAccountMapping,
            format!(
                "provider account {} is not a 12-digit AWS account ID",
                app.aws_account_id
            ),
        ),
        AppScope::Other { expected, observed } => (
            FindingKind::AccountMismatch,
            format!("Platform account {expected} · scanned account {observed}"),
        ),
        AppScope::Byoc { expected, observed } => (
            FindingKind::AccountMismatch,
            format!(
                "BYOC account {expected} · scanned account {} · customer AWS is not inspected",
                observed.as_deref().unwrap_or("unavailable")
            ),
        ),
        AppScope::InScope | AppScope::IdentityUnavailable => return None,
    };
    Some(AwsFinding {
        severity: DriftSeverity::Warning,
        kind,
        subject: app.name.clone(),
        platform: format!("{} · expected EC2 {}", app.state, app.provider_resource_id),
        aws: format!(
            "{} EC2 {} in {}",
            instance.state, instance.instance_id, instance.region
        ),
        scope: Some(scope),
        host_id: Some(instance.instance_id.clone()),
        resources: vec![app_summary(app)],
    })
}

fn lifecycle_finding(instance: &AwsInstance, app: &AwsAppRow) -> Option<AwsFinding> {
    let (severity, kind) = if app.destroyed || app.state == "terminated" {
        (
            instance_severity(instance),
            FindingKind::HostForTerminatedApp,
        )
    } else if matches!(app.state.as_str(), "initialized" | "failed") {
        (DriftSeverity::Warning, FindingKind::UnexpectedHost)
    } else if app.state == "running" && instance.state == "stopped" {
        (DriftSeverity::Critical, FindingKind::StateMismatch)
    } else if app.state == "stopped" && instance.state == "running" {
        (DriftSeverity::Warning, FindingKind::StateMismatch)
    } else {
        return None;
    };
    Some(AwsFinding {
        severity,
        kind,
        subject: app.name.clone(),
        platform: format!("{} · expected EC2 {}", app.state, app.provider_resource_id),
        aws: format!(
            "{} EC2 {} in {}",
            instance.state, instance.instance_id, instance.region
        ),
        scope: None,
        host_id: Some(instance.instance_id.clone()),
        resources: vec![app_summary(app)],
    })
}

#[allow(clippy::too_many_arguments)]
fn reconcile_tag_only<'a>(
    instance: &'a AwsInstance,
    classified: Option<CautionResourceKind>,
    account: Option<&str>,
    apps_by_id: &HashMap<String, &AwsAppRow>,
    builds_by_id: &HashMap<String, &AwsBuildRow>,
    tagged_expected: &mut HashMap<uuid::Uuid, Vec<&'a AwsInstance>>,
    observed_apps: &mut HashSet<uuid::Uuid>,
    result: &mut FindingResults,
) {
    match classified {
        Some(CautionResourceKind::Deployment) => {
            mark_caution(instance, result);
            let tagged = tag(&instance.tags, &["ResourceId", "caution:resource_id"])
                .and_then(|id| apps_by_id.get(id).copied());
            if let Some(app) = tagged {
                observed_apps.insert(app.id);
                result.app_hosts.push(tagged_host_row(instance, app));
                add_app_host_detail(instance, app, "ResourceId tag", account, result);
                if matches!(app_scope(app, account), AppScope::InScope)
                    && matches!(app.state.as_str(), "running" | "stopped")
                {
                    tagged_expected.entry(app.id).or_default().push(instance);
                } else {
                    let mut item = combined_app_finding(instance, app, app_scope(app, account))
                        .unwrap_or_else(|| link_finding(instance, app));
                    append_scope(
                        &mut item,
                        "ResourceId tag links this EC2 to the Platform app".to_string(),
                    );
                    result.findings.push(item);
                }
            } else {
                result.app_hosts.push(host_row(instance, None));
                result.hosts.push(AwsHost {
                    account: account.map(str::to_string),
                    instance: instance.clone(),
                    platform: None,
                });
                result.findings.push(AwsFinding {
                    severity: instance_severity(instance),
                    kind: FindingKind::UntrackedHost,
                    subject: instance.instance_id.clone(),
                    platform: "no Platform app or build matches its IDs or tags".to_string(),
                    aws: format!(
                        "{} Caution-tagged EC2 in {}",
                        instance.state, instance.region
                    ),
                    scope: None,
                    host_id: Some(instance.instance_id.clone()),
                    resources: Vec::new(),
                });
            }
        }
        Some(CautionResourceKind::Builder) => {
            mark_caution(instance, result);
            builders::reconcile_tagged_builder(instance, account, builds_by_id, result)
        }
        None => result.unrelated_instances += 1,
    }
}

fn link_finding(instance: &AwsInstance, app: &AwsAppRow) -> AwsFinding {
    AwsFinding {
        severity: DriftSeverity::Warning,
        kind: FindingKind::LinkMismatch,
        subject: app.name.clone(),
        platform: format!("{} · expected EC2 {}", app.state, app.provider_resource_id),
        aws: format!(
            "{} EC2 {} carries the app ResourceId tag",
            instance.state, instance.instance_id
        ),
        scope: Some("ResourceId tag disagrees with Platform host ID".to_string()),
        host_id: Some(instance.instance_id.clone()),
        resources: vec![app_summary(app)],
    }
}

fn add_app_host(
    instance: &AwsInstance,
    app: &AwsAppRow,
    relation: &str,
    account: Option<&str>,
    result: &mut FindingResults,
) {
    result.app_hosts.push(host_row(instance, Some(app)));
    add_app_host_detail(instance, app, relation, account, result);
}

fn add_app_host_detail(
    instance: &AwsInstance,
    app: &AwsAppRow,
    relation: &str,
    account: Option<&str>,
    result: &mut FindingResults,
) {
    result.hosts.push(AwsHost {
        account: account.map(str::to_string),
        instance: instance.clone(),
        platform: Some(AwsHostPlatform {
            resource: app_summary(app),
            state: app.state.clone(),
            expected_host: Some(app.provider_resource_id.clone()),
            account: Some(app.aws_account_id.clone()),
            relation: relation.to_string(),
        }),
    });
}

fn mark_caution(instance: &AwsInstance, result: &mut FindingResults) {
    result
        .caution_instances
        .insert(instance.instance_id.clone());
}

fn region_complete(region: Option<&str>, failed_regions: &HashSet<&str>) -> bool {
    region.map_or_else(
        || failed_regions.is_empty(),
        |region| !failed_regions.contains(region),
    )
}

fn push_resource(resources: &mut Vec<ResourceSummary>, resource: ResourceSummary) {
    if !resources
        .iter()
        .any(|existing| existing.kind == resource.kind && existing.id == resource.id)
    {
        resources.push(resource);
    }
}

fn append_scope(finding: &mut AwsFinding, scope: String) {
    finding.scope = Some(match finding.scope.take() {
        Some(existing) => format!("{existing} · {scope}"),
        None => scope,
    });
}

fn sort_findings(findings: &mut [AwsFinding]) {
    findings.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| left.kind.label().cmp(right.kind.label()))
            .then_with(|| left.subject.cmp(&right.subject))
    });
}

const fn severity_rank(severity: DriftSeverity) -> u8 {
    match severity {
        DriftSeverity::Critical => 0,
        DriftSeverity::Warning => 1,
        DriftSeverity::Info => 2,
    }
}

fn instance_severity(instance: &AwsInstance) -> DriftSeverity {
    if instance.state == "running" {
        DriftSeverity::Critical
    } else {
        DriftSeverity::Warning
    }
}

fn tag<'a>(tags: &'a HashMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| tags.get(*name).map(String::as_str))
}

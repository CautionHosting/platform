// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::HashMap;

use drift_detector::drift::{CautionResourceKind, DriftSeverity};

use super::{FindingResults, instance_severity, push_resource};
use crate::{
    aws::{
        AwsFinding, AwsHost, AwsHostPlatform, FindingKind,
        display::{build_summary, builder_row},
        inventory::AwsInstance,
    },
    db::aws::AwsBuildRow,
};

pub(super) fn reconcile_exact_build(
    instance: &AwsInstance,
    build: &AwsBuildRow,
    classified: Option<CautionResourceKind>,
    builds_by_id: &HashMap<String, &AwsBuildRow>,
    findings: &mut Vec<AwsFinding>,
) {
    let tagged = instance
        .tags
        .get("BuildId")
        .and_then(|id| builds_by_id.get(id).copied());
    let link_bad = classified == Some(CautionResourceKind::Deployment)
        || tagged.is_some_and(|tagged| tagged.id != build.id);
    if !active_build(&build.status) || link_bad {
        let mut resources = vec![build_summary(build)];
        if let Some(tagged) = tagged {
            push_resource(&mut resources, build_summary(tagged));
        }
        findings.push(AwsFinding {
            severity: if active_build(&build.status) {
                DriftSeverity::Warning
            } else {
                instance_severity(instance)
            },
            kind: if active_build(&build.status) {
                FindingKind::LinkMismatch
            } else {
                FindingKind::OrphanBuilder
            },
            subject: instance.instance_id.clone(),
            platform: format!("build {} is {}", build.id, build.status),
            aws: format!("{} builder EC2 {}", instance.state, instance.instance_id),
            scope: link_bad.then(|| "AWS tags disagree with the exact builder ID".to_string()),
            host_id: Some(instance.instance_id.clone()),
            resources,
        });
    }
}

pub(super) fn reconcile_tagged_builder(
    instance: &AwsInstance,
    account: Option<&str>,
    builds_by_id: &HashMap<String, &AwsBuildRow>,
    result: &mut FindingResults,
) {
    let build = instance
        .tags
        .get("BuildId")
        .and_then(|id| builds_by_id.get(id).copied());
    result.builders.push(builder_row(instance, build));
    add_host(instance, build, "BuildId tag", account, result);
    if build.is_none_or(|build| !active_build(&build.status)) {
        result.findings.push(AwsFinding {
            severity: instance_severity(instance),
            kind: FindingKind::OrphanBuilder,
            subject: instance.instance_id.clone(),
            platform: build.map_or_else(
                || "no active Platform build matches the BuildId tag".to_string(),
                |build| format!("build {} is {}", build.id, build.status),
            ),
            aws: format!(
                "{} Caution builder EC2 in {}",
                instance.state, instance.region
            ),
            scope: build.and_then(|build| {
                build
                    .builder_instance_id
                    .as_deref()
                    .filter(|expected| *expected != instance.instance_id)
                    .map(|expected| format!("Platform expects builder EC2 {expected}"))
            }),
            host_id: Some(instance.instance_id.clone()),
            resources: build.map(build_summary).into_iter().collect(),
        });
    } else if let Some(build) = build
        && build
            .builder_instance_id
            .as_deref()
            .is_some_and(|expected| expected != instance.instance_id)
    {
        result.findings.push(AwsFinding {
            severity: DriftSeverity::Warning,
            kind: FindingKind::LinkMismatch,
            subject: instance.instance_id.clone(),
            platform: format!(
                "active build {} expects {}",
                build.id,
                build.builder_instance_id.as_deref().unwrap_or("no builder")
            ),
            aws: format!("{} EC2 carries this BuildId tag", instance.state),
            scope: Some("BuildId tag disagrees with Platform builder instance ID".to_string()),
            host_id: Some(instance.instance_id.clone()),
            resources: vec![build_summary(build)],
        });
    }
}

pub(super) fn add_build_host(
    instance: &AwsInstance,
    build: &AwsBuildRow,
    account: Option<&str>,
    result: &mut FindingResults,
) {
    result.builders.push(builder_row(instance, Some(build)));
    add_host(
        instance,
        Some(build),
        "exact builder instance ID",
        account,
        result,
    );
}

fn add_host(
    instance: &AwsInstance,
    build: Option<&AwsBuildRow>,
    relation: &str,
    account: Option<&str>,
    result: &mut FindingResults,
) {
    result.hosts.push(AwsHost {
        account: account.map(str::to_string),
        instance: instance.clone(),
        platform: build.map(|build| AwsHostPlatform {
            resource: build_summary(build),
            state: build.status.clone(),
            expected_host: build.builder_instance_id.clone(),
            account: None,
            relation: relation.to_string(),
        }),
    });
}

fn active_build(status: &str) -> bool {
    matches!(status, "pending" | "building" | "uploading")
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{collections::HashMap, sync::Arc, time::Duration};

use aws_config::SdkConfig;
use aws_sdk_ec2::{Client, config::Region, types::Tag};
use drift_detector::aws::Ec2Inspector;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use futures_util::{StreamExt as _, stream};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const REGION_CONCURRENCY: usize = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AwsInstance {
    pub instance_id: String,
    pub region: String,
    pub availability_zone: Option<String>,
    pub launch_time_epoch_secs: Option<i64>,
    pub instance_type: Option<String>,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AwsVolume {
    pub volume_id: String,
    pub region: String,
    pub size_gib: i32,
    pub state: String,
    pub attached_instances: Vec<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AwsAddress {
    pub public_ip: String,
    pub region: String,
    pub instance_id: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryIssue {
    pub component: &'static str,
    pub region: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InventorySnapshot {
    pub regions_scanned: usize,
    pub regions_with_resources: usize,
    pub instance_regions_succeeded: usize,
    pub instances: Vec<AwsInstance>,
    pub volumes: Vec<AwsVolume>,
    pub addresses: Vec<AwsAddress>,
    pub issues: Vec<InventoryIssue>,
}

pub(crate) async fn fetch_inventory(
    config: &SdkConfig,
) -> Result<InventorySnapshot, FetchInventoryError> {
    use FetchInventoryErrorCtx as Ctx;

    let inspector = Arc::new(Ec2Inspector::from_sdk_config(config));
    let regions = tokio::time::timeout(REQUEST_TIMEOUT, inspector.enabled_regions())
        .await
        .with_context(Ctx::timeout())?
        .with_context(Ctx::discover_regions())?;
    let config = config.clone();
    let scans = stream::iter(regions.into_iter().map(|region| {
        let inspector = Arc::clone(&inspector);
        let config = config.clone();
        async move { scan_region(&config, &inspector, region).await }
    }))
    .buffer_unordered(REGION_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut snapshot = InventorySnapshot {
        regions_scanned: scans.len(),
        ..InventorySnapshot::default()
    };
    for scan in scans {
        if scan.instances_succeeded {
            snapshot.instance_regions_succeeded += 1;
        }
        if !scan.instances.is_empty() || !scan.volumes.is_empty() || !scan.addresses.is_empty() {
            snapshot.regions_with_resources += 1;
        }
        snapshot.instances.extend(scan.instances);
        snapshot.volumes.extend(scan.volumes);
        snapshot.addresses.extend(scan.addresses);
        snapshot.issues.extend(scan.issues);
    }
    normalize_inventory(&mut snapshot);
    Ok(snapshot)
}

fn normalize_inventory(snapshot: &mut InventorySnapshot) {
    snapshot
        .instances
        .sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
    snapshot.instances.dedup_by(|left, right| {
        left.instance_id == right.instance_id && left.region == right.region
    });
    snapshot
        .volumes
        .sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    snapshot
        .volumes
        .dedup_by(|left, right| left.volume_id == right.volume_id && left.region == right.region);
    snapshot.addresses.sort_by(|left, right| {
        left.region
            .cmp(&right.region)
            .then_with(|| left.public_ip.cmp(&right.public_ip))
    });
    snapshot
        .addresses
        .dedup_by(|left, right| left.region == right.region && left.public_ip == right.public_ip);
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum FetchInventoryError {
    #[error("failed to discover enabled AWS regions [{location:?}]")]
    DiscoverRegions {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("timed out discovering enabled AWS regions [{location:?}]")]
    Timeout {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn scan_region(config: &SdkConfig, inspector: &Ec2Inspector, region: String) -> RegionScan {
    let client = client_for_region(config, &region);
    let (instances, volumes, addresses) = tokio::join!(
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            inspector.list_live_instances_in_region(&region)
        ),
        list_volumes(&client, &region),
        list_addresses(&client, &region),
    );
    let mut scan = RegionScan::default();
    match instances {
        Ok(Ok(values)) => {
            scan.instances_succeeded = true;
            scan.instances = values
                .into_iter()
                .map(|instance| AwsInstance {
                    instance_id: instance.instance_id,
                    region: instance.region,
                    availability_zone: instance.availability_zone,
                    launch_time_epoch_secs: instance.launch_time_epoch_secs,
                    instance_type: instance.instance_type,
                    state: instance.state.as_str().to_string(),
                    public_ip: instance.public_ip,
                    private_ip: instance.private_ip,
                    vpc_id: instance.vpc_id,
                    subnet_id: instance.subnet_id,
                    tags: instance.tags,
                })
                .collect();
        }
        Ok(Err(error)) => scan.issues.push(issue("instances", &region, &error)),
        Err(_) => scan.issues.push(timeout_issue("instances", &region)),
    }
    match volumes {
        Ok(values) => scan.volumes = values,
        Err(error) => scan.issues.push(issue("volumes", &region, &error)),
    }
    match addresses {
        Ok(values) => scan.addresses = values,
        Err(error) => scan.issues.push(issue("public IPs", &region, &error)),
    }
    scan
}

#[derive(Default)]
struct RegionScan {
    instances_succeeded: bool,
    instances: Vec<AwsInstance>,
    volumes: Vec<AwsVolume>,
    addresses: Vec<AwsAddress>,
    issues: Vec<InventoryIssue>,
}

fn client_for_region(config: &SdkConfig, region: &str) -> Client {
    let mut builder = aws_sdk_ec2::config::Builder::from(config);
    builder.set_region(Some(Region::new(region.to_string())));
    Client::from_conf(builder.build())
}

async fn list_volumes(client: &Client, region: &str) -> Result<Vec<AwsVolume>, ListVolumesError> {
    use ListVolumesErrorCtx as Ctx;

    let mut paginator = client.describe_volumes().into_paginator().send();
    let mut volumes = Vec::new();
    loop {
        let page = tokio::time::timeout(REQUEST_TIMEOUT, paginator.next())
            .await
            .with_context(Ctx::timeout(region))?;
        let Some(page) = page else { break };
        let page = page.with_context(Ctx::request(region))?;
        volumes.extend(page.volumes().iter().filter_map(|volume| {
            Some(AwsVolume {
                volume_id: volume.volume_id()?.to_string(),
                region: region.to_string(),
                size_gib: volume.size().unwrap_or_default(),
                state: volume
                    .state()
                    .map_or("unknown", |state| state.as_str())
                    .to_string(),
                attached_instances: volume
                    .attachments()
                    .iter()
                    .filter_map(|attachment| attachment.instance_id().map(ToString::to_string))
                    .collect(),
                tags: tags(volume.tags()),
            })
        }));
    }
    Ok(volumes)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListVolumesError {
    #[error("failed to describe EBS volumes in {region} [{location:?}]")]
    Request {
        #[context(borrow = str)]
        region: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("timed out describing EBS volumes in {region} [{location:?}]")]
    Timeout {
        #[context(borrow = str)]
        region: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn list_addresses(
    client: &Client,
    region: &str,
) -> Result<Vec<AwsAddress>, ListAddressesError> {
    use ListAddressesErrorCtx as Ctx;

    let output = tokio::time::timeout(REQUEST_TIMEOUT, client.describe_addresses().send())
        .await
        .with_context(Ctx::timeout(region))?
        .with_context(Ctx::request(region))?;
    Ok(output
        .addresses()
        .iter()
        .filter_map(|address| {
            Some(AwsAddress {
                public_ip: address.public_ip()?.to_string(),
                region: region.to_string(),
                instance_id: address.instance_id().map(ToString::to_string),
                tags: tags(address.tags()),
            })
        })
        .collect())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListAddressesError {
    #[error("failed to describe public IPv4 addresses in {region} [{location:?}]")]
    Request {
        #[context(borrow = str)]
        region: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("timed out describing public IPv4 addresses in {region} [{location:?}]")]
    Timeout {
        #[context(borrow = str)]
        region: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn tags(values: &[Tag]) -> HashMap<String, String> {
    values
        .iter()
        .filter_map(|tag| Some((tag.key()?.to_string(), tag.value()?.to_string())))
        .collect()
}

fn issue(component: &'static str, region: &str, error: &dyn std::error::Error) -> InventoryIssue {
    let reason = if error_chain_contains(error, "accessdenied") {
        "access denied"
    } else {
        "request failed"
    };
    InventoryIssue {
        component,
        region: Some(region.to_string()),
        reason: reason.to_string(),
    }
}

fn timeout_issue(component: &'static str, region: &str) -> InventoryIssue {
    InventoryIssue {
        component,
        region: Some(region.to_string()),
        reason: "timed out".to_string(),
    }
}

pub(crate) fn error_chain_contains(error: &dyn std::error::Error, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    let mut current = Some(error);
    while let Some(error) = current {
        if error.to_string().to_ascii_lowercase().contains(&needle) {
            return true;
        }
        current = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{AwsAddress, InventorySnapshot, normalize_inventory};

    #[test]
    fn distinct_classic_addresses_in_one_region_are_retained() {
        let mut snapshot = InventorySnapshot {
            addresses: vec![
                address("203.0.113.2"),
                address("203.0.113.1"),
                address("203.0.113.1"),
            ],
            ..InventorySnapshot::default()
        };

        normalize_inventory(&mut snapshot);

        assert_eq!(snapshot.addresses.len(), 2);
        assert_eq!(snapshot.addresses[0].public_ip, "203.0.113.1");
        assert_eq!(snapshot.addresses[1].public_ip, "203.0.113.2");
    }

    fn address(public_ip: &str) -> AwsAddress {
        AwsAddress {
            public_ip: public_ip.to_string(),
            region: "us-east-1".to_string(),
            instance_id: None,
            tags: HashMap::new(),
        }
    }
}

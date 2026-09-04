// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AWS API client for querying actual resource state.
//!
//! This module provides a client to query the current state of AWS resources,
//! primarily EC2 instances, via the `aws-sdk-ec2` SDK. Instances can be
//! listed across every enabled region of an account, with the account's
//! configured region as the fallback when region discovery is unavailable.

use aws_config::SdkConfig;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ec2::config::Region;
use aws_sdk_ec2::error::SdkError as Ec2SdkError;
use aws_sdk_ec2::operation::describe_instances::DescribeInstancesError;
use aws_sdk_ec2::operation::describe_regions::DescribeRegionsError;
use aws_sdk_ec2::types::{Filter, Instance, InstanceStateName};
use std::collections::HashMap;
use thiserror::Error;

/// Error types for AWS API operations.
#[derive(Debug, Error)]
pub enum AwsError {
    /// Failed to describe EC2 instances in a region.
    #[error("failed to describe EC2 instances in region {region}")]
    DescribeInstances {
        /// The region that was queried.
        region: String,
        /// The underlying AWS SDK error.
        #[source]
        source: Box<Ec2SdkError<DescribeInstancesError>>,
    },
    /// Failed to discover the enabled AWS regions.
    #[error("failed to discover enabled AWS regions")]
    DescribeRegions(#[source] Box<Ec2SdkError<DescribeRegionsError>>),
}

/// Represents an EC2 instance in AWS.
#[derive(Debug, Clone)]
pub struct Ec2Instance {
    /// The EC2 instance ID (e.g. `i-0abcdef1234567890`).
    pub instance_id: String,
    /// The region the instance was observed in (e.g. `us-west-2`).
    pub region: String,
    /// The availability zone reported by AWS, when known.
    pub availability_zone: Option<String>,
    /// The instance launch time as Unix seconds, when known.
    pub launch_time_epoch_secs: Option<i64>,
    /// The instance type reported by AWS (e.g. `c5.xlarge`), when known.
    pub instance_type: Option<String>,
    /// The current lifecycle state reported by AWS.
    pub state: InstanceStateName,
    /// The public IPv4 address, when one is assigned.
    pub public_ip: Option<String>,
    /// The private IPv4 address, when one is assigned.
    pub private_ip: Option<String>,
    /// The VPC the instance is attached to, when known.
    pub vpc_id: Option<String>,
    /// The subnet the instance is attached to, when known.
    pub subnet_id: Option<String>,
    /// Instance tags as reported by AWS (e.g. `Name`). Tags without a key or
    /// value are omitted.
    pub tags: HashMap<String, String>,
}

/// AWS credentials for making API calls.
#[derive(Clone)]
pub struct AwsCredentials {
    /// The AWS access key ID. Empty when the default credential chain should be used.
    pub access_key_id: String,
    /// The AWS secret access key. Empty when the default credential chain should be used.
    pub secret_access_key: String,
    /// The region used as the base for API calls and as the fallback when
    /// region discovery is unavailable (e.g. `us-west-2`).
    pub region: String,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"***redacted***")
            .field("region", &self.region)
            .finish()
    }
}

/// Client for querying EC2 instances in AWS.
pub struct Ec2Inspector {
    /// The configured AWS EC2 API client.
    client: Ec2Client,
    /// The region this inspector is based in (used as the fallback when
    /// region discovery is unavailable).
    region: String,
    /// The resolved shared configuration, used to build per-region clients.
    sdk_config: SdkConfig,
}

impl Ec2Inspector {
    /// Create an EC2 inspector from an already-resolved AWS configuration.
    ///
    /// This keeps credentials and retry settings shared with other AWS clients.
    #[must_use]
    pub fn from_sdk_config(sdk_config: &SdkConfig) -> Self {
        let region = sdk_config
            .region()
            .map_or_else(|| "us-west-2".to_string(), ToString::to_string);
        let mut config = aws_sdk_ec2::config::Builder::from(sdk_config);
        config.set_region(Some(Region::new(region.clone())));
        Self {
            client: Ec2Client::from_conf(config.build()),
            region,
            sdk_config: sdk_config.clone(),
        }
    }

    /// Create a new EC2 inspector from credentials.
    ///
    /// Configuration loading does not perform any network I/O and cannot fail;
    /// invalid credentials are only rejected when an API call is made. When
    /// both credential fields are empty the default credential chain is used
    /// (with the given region) so that instance profiles and environment-based
    /// credentials work without static keys.
    pub async fn from_credentials(creds: &AwsCredentials) -> Self {
        let defaults = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_ec2::config::Region::new(creds.region.clone()));

        let sdk_config = if creds.access_key_id.is_empty() && creds.secret_access_key.is_empty() {
            defaults.load().await
        } else {
            defaults
                .credentials_provider(aws_sdk_ec2::config::Credentials::new(
                    &creds.access_key_id,
                    &creds.secret_access_key,
                    None,
                    None,
                    "drift-detector",
                ))
                .load()
                .await
        };

        let client = Ec2Client::new(&sdk_config);
        let region = creds.region.clone();

        Self {
            client,
            region,
            sdk_config,
        }
    }

    /// Create a new EC2 inspector from the default AWS config chain.
    ///
    /// The region is taken from the default config chain, falling back to
    /// `us-west-2` when none is configured.
    pub async fn from_env() -> Self {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let region = sdk_config
            .region()
            .map_or_else(|| "us-west-2".to_string(), ToString::to_string);

        Self {
            client: Ec2Client::new(&sdk_config),
            region,
            sdk_config,
        }
    }

    /// Build an EC2 client scoped to the given region, reusing the resolved
    /// configuration (credentials, retry policy, and so on).
    fn client_for_region(&self, region: &str) -> Ec2Client {
        let mut builder = aws_sdk_ec2::config::Builder::from(&self.sdk_config);
        builder.set_region(Some(aws_sdk_ec2::config::Region::new(region.to_string())));
        Ec2Client::from_conf(builder.build())
    }

    /// Describe instances by filter.
    ///
    /// Pages through all matching instances across reservations.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is based in.
    pub async fn describe_instances(
        &self,
        filters: &[Filter],
    ) -> Result<Vec<Ec2Instance>, AwsError> {
        Self::describe_instances_in_region(&self.client, filters, &self.region).await
    }

    /// Page through `DescribeInstances` in the given region, stamping each
    /// returned instance with that region.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails.
    async fn describe_instances_in_region(
        client: &Ec2Client,
        filters: &[Filter],
        region: &str,
    ) -> Result<Vec<Ec2Instance>, AwsError> {
        let mut paginator = client
            .describe_instances()
            .set_filters(Some(filters.to_vec()))
            .into_paginator()
            .send();

        let mut instances = Vec::new();

        while let Some(page) = paginator.next().await {
            let page = page.map_err(|source| AwsError::DescribeInstances {
                region: region.to_string(),
                source: Box::new(source),
            })?;

            for reservation in page.reservations() {
                for instance in reservation.instances() {
                    let ec2_instance = Self::convert_instance(instance, region);
                    if !ec2_instance.instance_id.is_empty() {
                        instances.push(ec2_instance);
                    }
                }
            }
        }

        Ok(instances)
    }

    /// Describe a specific instance by ID.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is based in.
    pub async fn describe_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<Ec2Instance>, AwsError> {
        let filters = vec![
            Filter::builder()
                .name("instance-id")
                .values(instance_id)
                .build(),
        ];

        let instances = self.describe_instances(&filters).await?;
        Ok(instances.into_iter().next())
    }

    /// List all running instances.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is based in.
    pub async fn list_running_instances(&self) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![
            Filter::builder()
                .name("instance-state-name")
                .values("running")
                .build(),
        ];

        self.describe_instances(&filters).await
    }

    /// List all instances that still exist in AWS: pending, running, stopping,
    /// or stopped.
    ///
    /// Terminated instances are excluded; AWS reaps them quickly and they
    /// cannot be drift-checked. Stopped instances are included so that
    /// stopped-but-chargeable resources are still compared and orphan
    /// detection can surface stopped instances that are not tracked in the
    /// database.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is based in.
    pub async fn list_live_instances(&self) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![live_instance_filter()];

        self.describe_instances(&filters).await
    }

    /// List the names of the enabled AWS regions, sorted ascending.
    ///
    /// Regions the account has not opted into are excluded, mirroring how the
    /// platform discovers deployment regions.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeRegions`] when the AWS API call fails.
    pub async fn enabled_regions(&self) -> Result<Vec<String>, AwsError> {
        let output = self
            .client
            .describe_regions()
            .all_regions(true)
            .send()
            .await
            .map_err(|source| AwsError::DescribeRegions(Box::new(source)))?;

        let mut regions: Vec<String> = output
            .regions()
            .iter()
            .filter(|region| region_usable(region.opt_in_status()))
            .filter_map(|region| region.region_name().map(ToString::to_string))
            .collect();
        regions.sort_unstable();
        regions.dedup();

        Ok(regions)
    }

    /// List all live instances in a specific region.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the given region.
    pub async fn list_live_instances_in_region(
        &self,
        region: &str,
    ) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![live_instance_filter()];

        let client = self.client_for_region(region);
        Self::describe_instances_in_region(&client, &filters, region).await
    }

    /// Find instances by tag.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is based in.
    pub async fn find_by_tag(&self, key: &str, value: &str) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![
            Filter::builder()
                .name(format!("tag:{key}"))
                .values(value)
                .build(),
        ];

        self.describe_instances(&filters).await
    }

    /// Convert an AWS SDK instance into the crate's domain model.
    ///
    /// Tags are copied from the AWS report; tags missing a key or value are
    /// omitted. When AWS does not report a state, the instance is treated as
    /// `running` rather than failing the conversion. The region the instance
    /// was observed in is recorded on the converted value.
    fn convert_instance(instance: &Instance, region: &str) -> Ec2Instance {
        let tags = instance
            .tags()
            .iter()
            .filter_map(|tag| {
                tag.key()
                    .zip(tag.value())
                    .map(|(key, value)| (key.to_string(), value.to_string()))
            })
            .collect();

        Ec2Instance {
            instance_id: instance.instance_id().unwrap_or_default().to_string(),
            region: region.to_string(),
            availability_zone: instance
                .placement()
                .and_then(|placement| placement.availability_zone())
                .map(ToString::to_string),
            launch_time_epoch_secs: instance.launch_time().map(|time| time.secs()),
            instance_type: instance.instance_type().map(|t| t.as_str().to_string()),
            state: match instance.state().and_then(|s| s.name()) {
                Some(s) => s.clone(),
                None => InstanceStateName::Running,
            },
            public_ip: instance.public_ip_address().map(ToString::to_string),
            private_ip: instance.private_ip_address().map(ToString::to_string),
            vpc_id: instance.vpc_id().map(ToString::to_string),
            subnet_id: instance.subnet_id().map(ToString::to_string),
            tags,
        }
    }

    /// Get the region this inspector is based in.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
}

/// Whether a region reported by `DescribeRegions` is usable by the account:
/// opt-in is not required, the account has opted in, or AWS did not report a
/// status at all.
fn region_usable(opt_in_status: Option<&str>) -> bool {
    opt_in_status.is_none_or(|status| matches!(status, "opt-in-not-required" | "opted-in"))
}

fn live_instance_filter() -> Filter {
    ["pending", "running", "stopping", "stopped"]
        .into_iter()
        .fold(
            Filter::builder().name("instance-state-name"),
            |filter, state| filter.values(state),
        )
        .build()
}

impl std::fmt::Debug for Ec2Inspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ec2Inspector")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::types::Tag;

    #[test]
    fn live_instance_filter_includes_stopping_hosts() {
        assert_eq!(
            live_instance_filter()
                .values()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["pending", "running", "stopping", "stopped"]
        );
    }

    #[test]
    fn test_aws_credentials_debug_redacts_secret() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            region: "us-west-2".to_string(),
        };

        let debug_str = format!("{:?}", creds);
        assert!(debug_str.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug_str.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_ec2_instance_debug() {
        let mut tags = HashMap::new();
        tags.insert("Name".to_string(), "test-instance".to_string());

        let instance = Ec2Instance {
            instance_id: "i-1234567890abcdef0".to_string(),
            region: "us-west-2".to_string(),
            availability_zone: Some("us-west-2a".to_string()),
            launch_time_epoch_secs: Some(1_788_000_000),
            instance_type: Some("c5.xlarge".to_string()),
            state: InstanceStateName::Running,
            public_ip: Some("54.123.45.67".to_string()),
            private_ip: Some("10.0.1.100".to_string()),
            vpc_id: Some("vpc-12345678".to_string()),
            subnet_id: Some("subnet-12345678".to_string()),
            tags,
        };

        let debug_str = format!("{:?}", instance);
        assert!(debug_str.contains("i-1234567890abcdef0"));
        assert!(debug_str.contains("us-west-2"));
        assert!(debug_str.contains("c5.xlarge"));
        assert!(debug_str.contains("Running"));
    }

    #[test]
    fn test_convert_instance_preserves_tags() {
        let instance = Instance::builder()
            .instance_id("i-1234567890abcdef0")
            .placement(
                aws_sdk_ec2::types::Placement::builder()
                    .availability_zone("eu-west-1a")
                    .build(),
            )
            .launch_time(aws_sdk_ec2::primitives::DateTime::from_secs(1_788_000_000))
            .private_ip_address("10.0.0.10")
            .vpc_id("vpc-1")
            .subnet_id("subnet-1")
            .tags(
                Tag::builder()
                    .key("ResourceId")
                    .value("550e8400-e29b-41d4-a716-446655440000")
                    .build(),
            )
            .tags(Tag::builder().key("Name").value("web-1").build())
            .build();

        let converted = Ec2Inspector::convert_instance(&instance, "eu-west-1");

        assert_eq!(converted.region, "eu-west-1");
        assert_eq!(converted.availability_zone.as_deref(), Some("eu-west-1a"));
        assert_eq!(converted.launch_time_epoch_secs, Some(1_788_000_000));
        assert_eq!(converted.private_ip.as_deref(), Some("10.0.0.10"));
        assert_eq!(converted.vpc_id.as_deref(), Some("vpc-1"));
        assert_eq!(converted.subnet_id.as_deref(), Some("subnet-1"));
        assert_eq!(converted.tags.len(), 2);
        assert_eq!(
            converted.tags.get("ResourceId"),
            Some(&"550e8400-e29b-41d4-a716-446655440000".to_string())
        );
        assert_eq!(converted.tags.get("Name"), Some(&"web-1".to_string()));
    }

    #[test]
    fn test_aws_error_display_includes_region() {
        let err = AwsError::DescribeInstances {
            region: "eu-west-1".to_string(),
            source: Box::new(Ec2SdkError::<DescribeInstancesError>::construction_failure(
                std::io::Error::other("boom"),
            )),
        };

        let display = err.to_string();
        assert!(
            display.contains("eu-west-1"),
            "unexpected display: {display}"
        );
    }

    #[test]
    fn test_aws_error_describe_regions_display() {
        let err = AwsError::DescribeRegions(Box::new(
            Ec2SdkError::<DescribeRegionsError>::construction_failure(std::io::Error::other(
                "boom",
            )),
        ));

        let display = err.to_string();
        assert_eq!(display, "failed to discover enabled AWS regions");
    }

    #[test]
    fn test_region_usable_filters_opt_in_status() {
        assert!(region_usable(None));
        assert!(region_usable(Some("opt-in-not-required")));
        assert!(region_usable(Some("opted-in")));
        assert!(!region_usable(Some("not-opted-in")));
    }
}

// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AWS API client for querying actual resource state.
//!
//! This module provides a client to query the current state of AWS resources,
//! primarily EC2 instances, via the `aws-sdk-ec2` SDK.

use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ec2::error::SdkError as Ec2SdkError;
use aws_sdk_ec2::operation::describe_instances::DescribeInstancesError;
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
        source: Ec2SdkError<DescribeInstancesError>,
    },
}

/// Represents an EC2 instance in AWS.
#[derive(Debug, Clone)]
pub struct Ec2Instance {
    /// The EC2 instance ID (e.g. `i-0abcdef1234567890`).
    pub instance_id: String,
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
    /// The region to query (e.g. `us-west-2`).
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
    /// The region this inspector queries.
    region: String,
}

impl Ec2Inspector {
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

        let config = if creds.access_key_id.is_empty() && creds.secret_access_key.is_empty() {
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

        let client = Ec2Client::new(&config);
        let region = creds.region.clone();

        Self { client, region }
    }

    /// Create a new EC2 inspector from the default AWS config chain.
    ///
    /// The region is taken from the default config chain, falling back to
    /// `us-west-2` when none is configured.
    pub async fn from_env() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let region = config
            .region()
            .map_or_else(|| "us-west-2".to_string(), ToString::to_string);

        Self {
            client: Ec2Client::new(&config),
            region,
        }
    }

    /// Describe instances by filter.
    ///
    /// Pages through all matching instances across reservations.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is configured for.
    pub async fn describe_instances(
        &self,
        filters: &[Filter],
    ) -> Result<Vec<Ec2Instance>, AwsError> {
        let mut paginator = self
            .client
            .describe_instances()
            .set_filters(Some(filters.to_vec()))
            .into_paginator()
            .send();

        let mut instances = Vec::new();

        while let Some(page) = paginator.next().await {
            let page = page.map_err(|source| AwsError::DescribeInstances {
                region: self.region.clone(),
                source,
            })?;

            for reservation in page.reservations() {
                for instance in reservation.instances() {
                    let ec2_instance = Self::convert_instance(instance);
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
    /// the region this inspector is configured for.
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
    /// the region this inspector is configured for.
    pub async fn list_running_instances(&self) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![
            Filter::builder()
                .name("instance-state-name")
                .values("running")
                .build(),
        ];

        self.describe_instances(&filters).await
    }

    /// List all instances that still exist in AWS: pending, running, or
    /// stopped.
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
    /// the region this inspector is configured for.
    pub async fn list_live_instances(&self) -> Result<Vec<Ec2Instance>, AwsError> {
        let filters = vec![
            Filter::builder()
                .name("instance-state-name")
                .values("pending")
                .values("running")
                .values("stopped")
                .build(),
        ];

        self.describe_instances(&filters).await
    }

    /// Find instances by tag.
    ///
    /// # Errors
    ///
    /// Returns [`AwsError::DescribeInstances`] when the AWS API call fails in
    /// the region this inspector is configured for.
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
    /// `running` rather than failing the conversion.
    fn convert_instance(instance: &Instance) -> Ec2Instance {
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

    /// Get the region this inspector is configured for.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
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
        assert!(debug_str.contains("c5.xlarge"));
        assert!(debug_str.contains("Running"));
    }

    #[test]
    fn test_convert_instance_preserves_tags() {
        let instance = Instance::builder()
            .instance_id("i-1234567890abcdef0")
            .tags(
                Tag::builder()
                    .key("ResourceId")
                    .value("550e8400-e29b-41d4-a716-446655440000")
                    .build(),
            )
            .tags(Tag::builder().key("Name").value("web-1").build())
            .build();

        let converted = Ec2Inspector::convert_instance(&instance);

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
            source: Ec2SdkError::<DescribeInstancesError>::construction_failure(
                std::io::Error::other("boom"),
            ),
        };

        let display = err.to_string();
        assert!(
            display.contains("eu-west-1"),
            "unexpected display: {display}"
        );
    }
}

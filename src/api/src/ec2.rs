// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

//! Minimal AWS clients using direct HTTP calls with SigV4 signing.
//! Replaces aws-sdk-ec2 and aws-sdk-autoscaling to avoid compiling massive generated SDKs.

use dterror::{BoxError, CtxError, Location, ResultExt};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use base64::Engine;

use crate::deployment::AwsCredentials;

pub struct RunInstancesParams {
    pub image_id: String,
    pub instance_type: String,
    pub user_data: String,
    pub iam_instance_profile: String,
    pub security_group_ids: Vec<String>,
    pub subnet_id: String,
    pub tags: Vec<(String, String)>,
}

pub struct Ec2Client {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    http: reqwest::Client,
}

pub struct Filter {
    pub name: String,
    pub values: Vec<String>,
}

pub struct Instance {
    pub instance_id: String,
    pub instance_type: Option<String>,
    pub tags: std::collections::HashMap<String, String>,
}

pub struct SecurityGroup {
    pub group_id: String,
    pub tags: std::collections::HashMap<String, String>,
}

pub struct Image {
    pub image_id: String,
    pub creation_date: String,
}

pub struct Region {
    pub name: String,
    pub opt_in_status: Option<String>,
}

/// An app's stable Elastic IP and the instance currently holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAddress {
    pub allocation_id: String,
    pub public_ip: String,
    /// `None` when the address is unassociated.
    pub instance_id: Option<String>,
}

/// Live EC2 runtime of one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRuntime {
    /// EC2 instance state name (`pending`, `running`, `stopped`, ...).
    pub state: String,
    /// `None` when the instance has no public IPv4 (for example while stopped).
    pub public_ip: Option<String>,
}

/// Failure modes for [`Ec2Client::count_vpcs`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CountVpcsError {
    #[error("failed to count VPCs [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::count_elastic_ips`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CountElasticIpsError {
    #[error("failed to count elastic IPs [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::active_instance_types`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ActiveInstanceTypesError {
    #[error("failed to get active instance types [{location}]")]
    Describe {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::describe_regions`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DescribeRegionsError {
    #[error("failed to describe regions [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::instance_type_offered`] and
/// [`Ec2Client::instance_type_offered_in_zone`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum InstanceTypeOfferedError {
    #[error("failed to check instance type offering [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`ServiceQuotasClient::get_service_quota_value`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetServiceQuotaValueError {
    #[error("failed to get service quota value [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Service quota response did not include Quota.Value [{location}]")]
    MissingQuotaValue { location: Location },
}

// Allow the EC2 host to use IMDSv2 while blocking metadata responses from
// traversing into Docker build containers.
const INSTANCE_METADATA_RESPONSE_HOP_LIMIT: &str = "1";

impl Filter {
    pub fn new(name: &str, values: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }
}

fn run_instances_request_params(params: &RunInstancesParams) -> Vec<(String, String)> {
    let user_data_b64 = base64::engine::general_purpose::STANDARD.encode(&params.user_data);

    let mut req_params = vec![
        ("Action".to_string(), "RunInstances".to_string()),
        ("Version".to_string(), "2016-11-15".to_string()),
        ("ImageId".to_string(), params.image_id.clone()),
        ("InstanceType".to_string(), params.instance_type.clone()),
        ("MinCount".to_string(), "1".to_string()),
        ("MaxCount".to_string(), "1".to_string()),
        ("UserData".to_string(), user_data_b64),
        ("SubnetId".to_string(), params.subnet_id.clone()),
        (
            "IamInstanceProfile.Name".to_string(),
            params.iam_instance_profile.clone(),
        ),
        (
            "MetadataOptions.HttpTokens".to_string(),
            "required".to_string(),
        ),
        (
            "MetadataOptions.HttpPutResponseHopLimit".to_string(),
            INSTANCE_METADATA_RESPONSE_HOP_LIMIT.to_string(),
        ),
        (
            "BlockDeviceMapping.1.DeviceName".to_string(),
            "/dev/xvda".to_string(),
        ),
        (
            "BlockDeviceMapping.1.Ebs.VolumeSize".to_string(),
            "50".to_string(),
        ),
        (
            "BlockDeviceMapping.1.Ebs.VolumeType".to_string(),
            "gp3".to_string(),
        ),
        (
            "BlockDeviceMapping.1.Ebs.Encrypted".to_string(),
            "true".to_string(),
        ),
    ];

    for (i, sg_id) in params.security_group_ids.iter().enumerate() {
        req_params.push((format!("SecurityGroupId.{}", i + 1), sg_id.clone()));
    }

    if !params.tags.is_empty() {
        req_params.push((
            "TagSpecification.1.ResourceType".to_string(),
            "instance".to_string(),
        ));
        for (i, (key, value)) in params.tags.iter().enumerate() {
            let idx = i + 1;
            req_params.push((format!("TagSpecification.1.Tag.{}.Key", idx), key.clone()));
            req_params.push((
                format!("TagSpecification.1.Tag.{}.Value", idx),
                value.clone(),
            ));
        }
    }

    req_params
}

/// Failure modes for [`Ec2Client::signed_request`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum Ec2SignedRequestError {
    #[error("EC2 API request failed")]
    Request {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::describe_instances`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DescribeInstancesError {
    #[error("EC2 DescribeInstances request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl DescribeInstancesError {
    pub(crate) fn client_message(&self) -> &'static str {
        "EC2 DescribeInstances request failed"
    }
}

/// Failure modes for [`Ec2Client::terminate_instances`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TerminateInstancesError {
    #[error("EC2 TerminateInstances request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::describe_security_groups`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DescribeSecurityGroupsError {
    #[error("EC2 DescribeSecurityGroups request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::subnet_zones`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SubnetZonesError {
    #[error("EC2 DescribeSubnets request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::delete_security_group`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteSecurityGroupError {
    #[error("EC2 DeleteSecurityGroup request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::stop_instances`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum StopInstancesError {
    #[error("EC2 StopInstances request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl StopInstancesError {
    pub(crate) fn client_message(&self) -> &'static str {
        "EC2 API request failed"
    }
}

/// Failure modes for [`Ec2Client::start_instances`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum StartInstancesError {
    #[error("EC2 StartInstances request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl StartInstancesError {
    pub(crate) fn client_message(&self) -> &'static str {
        "EC2 API request failed"
    }
}

/// Failure modes for [`Ec2Client::run_instances`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RunInstancesError {
    #[error("EC2 RunInstances request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("RunInstances response did not contain an instance ID [{location}]")]
    MissingInstanceId { location: Location },
}

/// Failure modes for [`Ec2Client::latest_amazon_linux_2023_ami_id`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LatestAmazonLinuxAmiError {
    #[error("EC2 DescribeImages request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("No Amazon Linux 2023 AMI returned by DescribeImages [{location}]")]
    NoAmi { location: Location },
}

/// Failure modes for [`Ec2Client::find_security_group_id`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum FindSecurityGroupError {
    #[error("EC2 DescribeSecurityGroups request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::create_security_group`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateSecurityGroupError {
    #[error("EC2 CreateSecurityGroup request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("CreateSecurityGroup response did not contain a groupId [{location}]")]
    MissingGroupId { location: Location },
}

/// Failure modes for [`Ec2Client::associate_address`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AssociateAddressError {
    #[error("EC2 AssociateAddress request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::associate_app_address`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AssociateAppAddressError {
    #[error("could not describe Elastic IP addresses [{location}]")]
    DescribeAddresses {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not parse app Elastic IP address [{location}]")]
    ParseAddress {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not associate Elastic IP address [{location}]")]
    AssociateAddress {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl AssociateAppAddressError {
    pub(crate) fn client_message(&self) -> &'static str {
        match self {
            Self::DescribeAddresses { .. } => "EC2 API request failed",
            Self::ParseAddress { .. } => "expected exactly one Elastic IP tagged for app",
            Self::AssociateAddress { .. } => "EC2 API request failed",
        }
    }
}

/// Failure modes for [`parse_app_address`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, caution_error::ProviderError)]
pub(crate) enum ParseAppAddressError {
    #[error("expected exactly one Elastic IP tagged for app")]
    NotExactlyOne {
        #[provide]
        location: Location,
    },
}

/// Failure modes for [`Ec2Client::describe_app_address`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum DescribeAppAddressError {
    #[error("could not describe Elastic IP addresses")]
    DescribeAddresses {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not parse app Elastic IP address")]
    ParseAddress {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Ec2Client::move_app_address`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum MoveAppAddressError {
    #[error("could not read the app Elastic IP address")]
    DescribeAddress {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    /// The address is held by someone other than the expected holder. Nothing
    /// was moved.
    #[error(
        "app Elastic IP is held by {}, expected {}",
        holder_label(.actual),
        holder_label(.expected)
    )]
    HolderMismatch {
        /// Instance the caller expected to hold the address (`None` =
        /// unassociated).
        expected: Option<String>,
        /// Instance that holds the address now (`None` = unassociated).
        actual: Option<String>,
        #[provide]
        location: Location,
    },

    #[error("could not associate Elastic IP address")]
    AssociateAddress {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn holder_label(holder: &Option<String>) -> &str {
    holder.as_deref().unwrap_or("no instance")
}

/// Failure modes for [`Ec2Client::describe_instance_runtime`].
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum DescribeInstanceRuntimeError {
    #[error("EC2 DescribeInstances request failed")]
    Request {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not parse the EC2 DescribeInstances response")]
    Parse {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`parse_instance_runtime`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, caution_error::ProviderError)]
pub(crate) enum ParseInstanceRuntimeError {
    #[error("DescribeInstances response has no reservation set")]
    NoReservationSet {
        #[provide]
        location: Location,
    },
    #[error("DescribeInstances response lists an instance without a state")]
    NoState {
        #[provide]
        location: Location,
    },
}

/// What [`Ec2Client::move_app_address`] has to do to reach the target.
#[derive(Debug, PartialEq, Eq)]
enum AppAddressMove {
    /// The target already holds the address (an idempotent retry).
    AlreadyAtTarget,
    Associate {
        /// `false` makes AWS refuse if anyone holds the address by then.
        allow_reassociation: bool,
    },
}

/// Decide how to move `address` to `target`, refusing an unexpected holder.
#[track_caller]
fn plan_app_address_move(
    address: &AppAddress,
    target: &str,
    expected_holder: Option<&str>,
) -> Result<AppAddressMove, MoveAppAddressError> {
    if address.instance_id.as_deref() == Some(target) {
        return Ok(AppAddressMove::AlreadyAtTarget);
    }
    if address.instance_id.as_deref() != expected_holder {
        return Err(MoveAppAddressError::HolderMismatch {
            expected: expected_holder.map(str::to_string),
            actual: address.instance_id.clone(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(AppAddressMove::Associate {
        allow_reassociation: expected_holder.is_some(),
    })
}

fn associate_address_params(
    allocation_id: &str,
    instance_id: &str,
    allow_reassociation: bool,
) -> Vec<(String, String)> {
    vec![
        ("Action".to_string(), "AssociateAddress".to_string()),
        ("Version".to_string(), "2016-11-15".to_string()),
        ("AllocationId".to_string(), allocation_id.to_string()),
        ("InstanceId".to_string(), instance_id.to_string()),
        (
            "AllowReassociation".to_string(),
            allow_reassociation.to_string(),
        ),
    ]
}

impl Ec2Client {
    pub fn new(credentials: &AwsCredentials) -> Self {
        Self {
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.clone(),
            region: credentials.region.clone(),
            // A hung EC2 call must not hold the app operation lock indefinitely.
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("static reqwest client configuration"),
        }
    }

    /// The region this client is pinned to.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// A client with the same credentials and HTTP connection pool, targeting
    /// another region.
    pub fn for_region(&self, region: &str) -> Self {
        Self {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            region: region.to_string(),
            http: self.http.clone(),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn describe_instances(
        &self,
        filters: &[Filter],
    ) -> Result<Vec<Instance>, DescribeInstancesError> {
        use DescribeInstancesErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "DescribeInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        params.extend(filter_params(filters));

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_instance_ids(&body))
    }

    /// The security groups matching every filter, with their tags.
    #[tracing::instrument(skip_all, err)]
    pub async fn describe_security_groups(
        &self,
        filters: &[Filter],
    ) -> Result<Vec<SecurityGroup>, DescribeSecurityGroupsError> {
        use DescribeSecurityGroupsErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "DescribeSecurityGroups".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        params.extend(filter_params(filters));

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_security_groups(&body))
    }

    /// Fails (`DependencyViolation`) while an instance still uses the group.
    #[tracing::instrument(skip_all, err)]
    pub async fn delete_security_group(
        &self,
        group_id: &str,
    ) -> Result<(), DeleteSecurityGroupError> {
        use DeleteSecurityGroupErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DeleteSecurityGroup".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("GroupId".to_string(), group_id.to_string()),
        ];
        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn count_vpcs(&self) -> Result<u32, CountVpcsError> {
        use CountVpcsErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeVpcs".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_tag_values(&body, "vpcId").len() as u32)
    }

    #[tracing::instrument(skip_all)]
    pub async fn count_elastic_ips(&self) -> Result<u32, CountElasticIpsError> {
        use CountElasticIpsErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeAddresses".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_tag_values(&body, "publicIp").len() as u32)
    }

    #[tracing::instrument(skip_all)]
    pub async fn associate_app_address(
        &self,
        resource_id: &str,
        instance_id: &str,
    ) -> Result<String, AssociateAppAddressError> {
        use AssociateAppAddressErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeAddresses".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Filter.1.Name".to_string(), "tag:ResourceId".to_string()),
            ("Filter.1.Value.1".to_string(), resource_id.to_string()),
        ];
        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::describe_addresses())?;
        let (allocation_id, public_ip, attached_instance_id) =
            parse_app_address(&body).with_context(Ctx::parse_address())?;
        if attached_instance_id.as_deref() != Some(instance_id) {
            self.associate_address(&allocation_id, instance_id)
                .await
                .with_context(Ctx::associate_address())?;
        }
        Ok(public_ip)
    }

    /// The app's Elastic IP (tagged `ResourceId`) and its current holder.
    #[tracing::instrument(skip_all, err)]
    pub async fn describe_app_address(
        &self,
        resource_id: &str,
    ) -> Result<AppAddress, DescribeAppAddressError> {
        use DescribeAppAddressErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeAddresses".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Filter.1.Name".to_string(), "tag:ResourceId".to_string()),
            ("Filter.1.Value.1".to_string(), resource_id.to_string()),
        ];
        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::describe_addresses())?;
        let (allocation_id, public_ip, instance_id) =
            parse_app_address(&body).with_context(Ctx::parse_address())?;
        Ok(AppAddress {
            allocation_id,
            public_ip,
            instance_id,
        })
    }

    /// Moves the app EIP to `target` only if it is currently held by
    /// `expected_holder` (`None` = unassociated). Returns the EIP.
    ///
    /// Already being at `target` succeeds, so retries are safe. Any other
    /// holder fails with [`MoveAppAddressError::HolderMismatch`]. Without an
    /// expected holder AWS itself refuses if the address got associated since
    /// it was read.
    #[tracing::instrument(skip_all, err)]
    pub async fn move_app_address(
        &self,
        resource_id: &str,
        target: &str,
        expected_holder: Option<&str>,
    ) -> Result<String, MoveAppAddressError> {
        use MoveAppAddressErrorCtx as Ctx;

        let address = self
            .describe_app_address(resource_id)
            .await
            .with_context(Ctx::describe_address())?;
        match plan_app_address_move(&address, target, expected_holder)? {
            AppAddressMove::AlreadyAtTarget => {}
            AppAddressMove::Associate {
                allow_reassociation,
            } => {
                let params =
                    associate_address_params(&address.allocation_id, target, allow_reassociation);
                self.signed_request(&params)
                    .await
                    .with_context(Ctx::associate_address())?;
            }
        }
        Ok(address.public_ip)
    }

    /// The live runtime of an instance, or `None` when EC2 does not know it.
    #[tracing::instrument(skip_all, err)]
    pub async fn describe_instance_runtime(
        &self,
        instance_id: &str,
    ) -> Result<Option<InstanceRuntime>, DescribeInstanceRuntimeError> {
        let params = vec![
            ("Action".to_string(), "DescribeInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("InstanceId.1".to_string(), instance_id.to_string()),
        ];
        // The free request keeps the AWS error code that the boxed
        // `Ec2Client::signed_request` error hides.
        instance_runtime(
            signed_request(
                &self.http,
                &self.access_key_id,
                &self.secret_access_key,
                &self.region,
                "ec2",
                &params,
            )
            .await,
        )
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn active_instance_types(&self) -> Result<Vec<String>, ActiveInstanceTypesError> {
        use ActiveInstanceTypesErrorCtx as Ctx;

        let instances = self
            .describe_instances(&[Filter::new("instance-state-name", &["pending", "running"])])
            .await
            .with_context(Ctx::describe())?;

        Ok(instances
            .into_iter()
            .filter_map(|instance| instance.instance_type)
            .collect())
    }

    #[tracing::instrument(skip_all)]
    pub async fn describe_regions(
        &self,
        all_regions: bool,
    ) -> Result<Vec<Region>, DescribeRegionsError> {
        use DescribeRegionsErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "DescribeRegions".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        if all_regions {
            params.push(("AllRegions".to_string(), "true".to_string()));
        }

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_regions(&body))
    }

    #[tracing::instrument(skip_all)]
    pub async fn instance_type_offered(
        &self,
        instance_type: &str,
    ) -> Result<bool, InstanceTypeOfferedError> {
        use InstanceTypeOfferedErrorCtx as Ctx;

        let params = vec![
            (
                "Action".to_string(),
                "DescribeInstanceTypeOfferings".to_string(),
            ),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("LocationType".to_string(), "region".to_string()),
            ("Filter.1.Name".to_string(), "instance-type".to_string()),
            ("Filter.1.Value.1".to_string(), instance_type.to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(!parse_tag_values(&body, "instanceType").is_empty())
    }

    /// Whether `instance_type` is offered in the availability zone `zone`.
    #[tracing::instrument(skip_all, err)]
    pub async fn instance_type_offered_in_zone(
        &self,
        instance_type: &str,
        zone: &str,
    ) -> Result<bool, InstanceTypeOfferedError> {
        use InstanceTypeOfferedErrorCtx as Ctx;

        let params = vec![
            (
                "Action".to_string(),
                "DescribeInstanceTypeOfferings".to_string(),
            ),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("LocationType".to_string(), "availability-zone".to_string()),
            ("Filter.1.Name".to_string(), "instance-type".to_string()),
            ("Filter.1.Value.1".to_string(), instance_type.to_string()),
            ("Filter.2.Name".to_string(), "location".to_string()),
            ("Filter.2.Value.1".to_string(), zone.to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(!parse_tag_values(&body, "instanceType").is_empty())
    }

    /// The availability zone of each of `subnet_ids`.
    #[tracing::instrument(skip_all, err)]
    pub async fn subnet_zones(
        &self,
        subnet_ids: &[String],
    ) -> Result<std::collections::HashMap<String, String>, SubnetZonesError> {
        use SubnetZonesErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "DescribeSubnets".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (index, subnet_id) in subnet_ids.iter().enumerate() {
            params.push((format!("SubnetId.{}", index + 1), subnet_id.clone()));
        }
        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_subnet_zones(&body))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn stop_instances(&self, instance_ids: &[String]) -> Result<(), StopInstancesError> {
        use StopInstancesErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "StopInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn start_instances(
        &self,
        instance_ids: &[String],
    ) -> Result<(), StartInstancesError> {
        use StartInstancesErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "StartInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn run_instances(
        &self,
        params: &RunInstancesParams,
    ) -> Result<String, RunInstancesError> {
        use RunInstancesErrorCtx as Ctx;

        let req_params = run_instances_request_params(params);

        let body = self
            .signed_request(&req_params)
            .await
            .with_context(Ctx::request())?;

        // Parse instance ID from RunInstances response
        let instances = parse_instance_ids(&body);
        instances
            .into_iter()
            .next()
            .map(|i| i.instance_id)
            .ok_or_else(|| RunInstancesError::MissingInstanceId {
                location: std::panic::Location::caller(),
            })
    }

    #[tracing::instrument(skip_all)]
    pub async fn latest_amazon_linux_2023_ami_id(
        &self,
    ) -> Result<String, LatestAmazonLinuxAmiError> {
        use LatestAmazonLinuxAmiErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeImages".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Owner.1".to_string(), "amazon".to_string()),
            ("Filter.1.Name".to_string(), "name".to_string()),
            (
                "Filter.1.Value.1".to_string(),
                "al2023-ami-*-x86_64".to_string(),
            ),
            (
                "Filter.2.Name".to_string(),
                "virtualization-type".to_string(),
            ),
            ("Filter.2.Value.1".to_string(), "hvm".to_string()),
            ("Filter.3.Name".to_string(), "root-device-type".to_string()),
            ("Filter.3.Value.1".to_string(), "ebs".to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        let mut images = parse_images(&body);
        images.sort_by(|left, right| left.creation_date.cmp(&right.creation_date));
        images
            .pop()
            .map(|image| image.image_id)
            .ok_or_else(|| LatestAmazonLinuxAmiError::NoAmi {
                location: std::panic::Location::caller(),
            })
    }

    #[tracing::instrument(skip_all)]
    pub async fn find_security_group_id(
        &self,
        vpc_id: &str,
        group_name: &str,
    ) -> Result<Option<String>, FindSecurityGroupError> {
        use FindSecurityGroupErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "DescribeSecurityGroups".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Filter.1.Name".to_string(), "vpc-id".to_string()),
            ("Filter.1.Value.1".to_string(), vpc_id.to_string()),
            ("Filter.2.Name".to_string(), "group-name".to_string()),
            ("Filter.2.Value.1".to_string(), group_name.to_string()),
        ];

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(parse_first_tag_value(&body, "groupId"))
    }

    #[tracing::instrument(skip_all)]
    pub async fn create_security_group(
        &self,
        group_name: &str,
        description: &str,
        vpc_id: &str,
        tags: &[(String, String)],
    ) -> Result<String, CreateSecurityGroupError> {
        use CreateSecurityGroupErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "CreateSecurityGroup".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("GroupName".to_string(), group_name.to_string()),
            ("GroupDescription".to_string(), description.to_string()),
            ("VpcId".to_string(), vpc_id.to_string()),
        ];

        if !tags.is_empty() {
            params.push((
                "TagSpecification.1.ResourceType".to_string(),
                "security-group".to_string(),
            ));
            for (index, (key, value)) in tags.iter().enumerate() {
                let idx = index + 1;
                params.push((format!("TagSpecification.1.Tag.{}.Key", idx), key.clone()));
                params.push((
                    format!("TagSpecification.1.Tag.{}.Value", idx),
                    value.clone(),
                ));
            }
        }

        let body = self
            .signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        parse_first_tag_value(&body, "groupId").ok_or_else(|| {
            CreateSecurityGroupError::MissingGroupId {
                location: std::panic::Location::caller(),
            }
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn terminate_instances(
        &self,
        instance_ids: &[String],
    ) -> Result<(), TerminateInstancesError> {
        use TerminateInstancesErrorCtx as Ctx;

        let mut params = vec![
            ("Action".to_string(), "TerminateInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn associate_address(
        &self,
        allocation_id: &str,
        instance_id: &str,
    ) -> Result<(), AssociateAddressError> {
        use AssociateAddressErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "AssociateAddress".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("AllocationId".to_string(), allocation_id.to_string()),
            ("InstanceId".to_string(), instance_id.to_string()),
        ];

        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn signed_request(
        &self,
        params: &[(String, String)],
    ) -> Result<String, Ec2SignedRequestError> {
        use Ec2SignedRequestErrorCtx as Ctx;

        let body = signed_request(
            &self.http,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "ec2",
            params,
        )
        .await
        .with_context(Ctx::request())?;
        Ok(body)
    }
}

pub struct ServiceQuotasClient {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    http: reqwest::Client,
}

impl ServiceQuotasClient {
    pub fn new(credentials: &AwsCredentials) -> Self {
        Self {
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.clone(),
            region: credentials.region.clone(),
            http: reqwest::Client::new(),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_service_quota_value(
        &self,
        service_code: &str,
        quota_code: &str,
    ) -> Result<f64, GetServiceQuotaValueError> {
        use GetServiceQuotaValueErrorCtx as Ctx;

        let body = serde_json::json!({
            "ServiceCode": service_code,
            "QuotaCode": quota_code,
        });

        let response = signed_json_request(
            &self.http,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "servicequotas",
            "ServiceQuotasV20190624.GetServiceQuota",
            &body,
        )
        .await
        .with_context(Ctx::request())?;

        response
            .get("Quota")
            .and_then(|quota| quota.get("Value"))
            .and_then(|value| value.as_f64())
            .ok_or_else(|| GetServiceQuotaValueError::MissingQuotaValue {
                location: std::panic::Location::caller(),
            })
    }
}

pub struct AsgClient {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    http: reqwest::Client,
}

/// Failure modes for [`AsgClient::signed_request`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AsgSignedRequestError {
    #[error("Auto Scaling API request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`AsgClient::set_desired_capacity`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetDesiredCapacityError {
    #[error("Auto Scaling SetDesiredCapacity request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`AsgClient::update_auto_scaling_group`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateAutoScalingGroupError {
    #[error("Auto Scaling UpdateAutoScalingGroup request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl AsgClient {
    pub fn new(credentials: &AwsCredentials) -> Self {
        Self {
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.clone(),
            region: credentials.region.clone(),
            http: reqwest::Client::new(),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn set_desired_capacity(
        &self,
        asg_name: &str,
        desired_capacity: i32,
    ) -> Result<(), SetDesiredCapacityError> {
        use SetDesiredCapacityErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "SetDesiredCapacity".to_string()),
            ("Version".to_string(), "2011-01-01".to_string()),
            ("AutoScalingGroupName".to_string(), asg_name.to_string()),
            ("DesiredCapacity".to_string(), desired_capacity.to_string()),
        ];

        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn update_auto_scaling_group(
        &self,
        asg_name: &str,
        launch_template_id: &str,
    ) -> Result<(), UpdateAutoScalingGroupError> {
        use UpdateAutoScalingGroupErrorCtx as Ctx;

        let params = vec![
            ("Action".to_string(), "UpdateAutoScalingGroup".to_string()),
            ("Version".to_string(), "2011-01-01".to_string()),
            ("AutoScalingGroupName".to_string(), asg_name.to_string()),
            (
                "LaunchTemplate.LaunchTemplateId".to_string(),
                launch_template_id.to_string(),
            ),
            ("LaunchTemplate.Version".to_string(), "$Latest".to_string()),
        ];

        self.signed_request(&params)
            .await
            .with_context(Ctx::request())?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn signed_request(
        &self,
        params: &[(String, String)],
    ) -> Result<String, AsgSignedRequestError> {
        use AsgSignedRequestErrorCtx as Ctx;

        let body = signed_request(
            &self.http,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "autoscaling",
            params,
        )
        .await
        .with_context(Ctx::request())?;
        Ok(body)
    }
}

/// Failure modes for the free [`signed_request`] helper.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedRequestError {
    #[error("{service} API request failed [{location}]")]
    Http {
        #[context(borrow = str)]
        service: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{service} API returned {status} [{location}]")]
    NonSuccess {
        service: String,
        status: u16,
        /// The AWS error `Code` from the response body, when it has one.
        aws_code: Option<String>,
        location: Location,
    },

    #[error("Failed to read {service} response [{location}]")]
    ReadResponse {
        #[context(borrow = str)]
        service: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all)]
async fn signed_request(
    http: &reqwest::Client,
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    params: &[(String, String)],
) -> Result<String, SignedRequestError> {
    use SignedRequestErrorCtx as Ctx;

    let host = format!("{}.{}.amazonaws.com", service, region);
    let url = format!("https://{}/", host);
    let body = encode_form(params);

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let content_type = "application/x-www-form-urlencoded; charset=utf-8";

    // Canonical request
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-date:{}\n",
        content_type, host, amz_date
    );
    let signed_headers = "content-type;host;x-amz-date";
    let canonical_request = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, payload_hash
    );

    // String to sign
    let scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Signing key
    let signing_key = derive_signing_key(secret_access_key, &date_stamp, region, service);

    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key_id, scope, signed_headers, signature
    );

    let response = http
        .post(&url)
        .header("Content-Type", content_type)
        .header("Host", &host)
        .header("X-Amz-Date", &amz_date)
        .header("Authorization", &authorization)
        .body(body)
        .send()
        .await
        .with_context(Ctx::http(service))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(Ctx::read_response(service))?;

    if !status.is_success() {
        return Err(signed_request_non_success(service, status.as_u16(), &text));
    }

    Ok(text)
}

/// A non-success AWS response; keeps the error `Code` from the XML body.
#[track_caller]
fn signed_request_non_success(service: &str, status: u16, body: &str) -> SignedRequestError {
    SignedRequestError::NonSuccess {
        service: service.to_string(),
        status,
        aws_code: parse_first_tag_value(body, "Code"),
        location: std::panic::Location::caller(),
    }
}

/// Failure modes for the free [`signed_json_request`] helper.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedJsonRequestError {
    #[error("Failed to serialize AWS JSON body [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{service} API request failed [{location}]")]
    Http {
        #[context(borrow = str)]
        service: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{service} API returned {status}: {response_body} [{location}]")]
    NonSuccess {
        service: String,
        status: u16,
        response_body: String,
        location: Location,
    },

    #[error("Failed to read {service} response [{location}]")]
    ReadResponse {
        #[context(borrow = str)]
        service: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to parse {service} response JSON [{location}]")]
    ParseJson {
        #[context(borrow = str)]
        service: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all)]
async fn signed_json_request(
    http: &reqwest::Client,
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    target: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, SignedJsonRequestError> {
    use SignedJsonRequestErrorCtx as Ctx;

    let host = format!("{}.{}.amazonaws.com", service, region);
    let url = format!("https://{}/", host);
    let body = serde_json::to_string(body).with_context(Ctx::serialize())?;

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let content_type = "application/x-amz-json-1.1";
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-amz-date:{}\nx-amz-target:{}\n",
        content_type, host, amz_date, target
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-target";
    let canonical_request = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, payload_hash
    );

    let scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = derive_signing_key(secret_access_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key_id, scope, signed_headers, signature
    );

    let response = http
        .post(&url)
        .header("Content-Type", content_type)
        .header("Host", &host)
        .header("X-Amz-Date", &amz_date)
        .header("X-Amz-Target", target)
        .header("Authorization", &authorization)
        .body(body)
        .send()
        .await
        .with_context(Ctx::http(service))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(Ctx::read_response(service))?;

    if !status.is_success() {
        return Err(SignedJsonRequestError::NonSuccess {
            service: service.to_string(),
            status: status.as_u16(),
            response_body: text,
            location: std::panic::Location::caller(),
        });
    }

    serde_json::from_str(&text).with_context(Ctx::parse_json(service))
}

fn filter_params(filters: &[Filter]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    for (i, filter) in filters.iter().enumerate() {
        let idx = i + 1;
        params.push((format!("Filter.{}.Name", idx), filter.name.clone()));
        for (j, value) in filter.values.iter().enumerate() {
            params.push((format!("Filter.{}.Value.{}", idx, j + 1), value.clone()));
        }
    }
    params
}

fn encode_form(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Extract instances from EC2 DescribeInstances XML response.
///
/// Each `<instancesSet>` is walked item-by-item so tags stay grouped with
/// their owning instance; a flat scan of tag names would mix tags from
/// different instances together.
fn parse_instance_ids(xml: &str) -> Vec<Instance> {
    let mut instances = Vec::new();

    for set in top_level_blocks(xml, "<instancesSet>", "</instancesSet>") {
        for item in top_level_blocks(set, "<item>", "</item>") {
            let Some(instance_id) = parse_first_tag_value(item, "instanceId") else {
                continue;
            };
            instances.push(Instance {
                instance_id,
                instance_type: parse_first_tag_value(item, "instanceType"),
                tags: parse_tag_set(item),
            });
        }
    }

    instances
}

/// Return the contents of each top-level `<open>`...`</open>` element in
/// `xml`, tracking one level of nesting so a nested occurrence of the same
/// tag (e.g. `tagSet` `<item>`s inside an instance `<item>`) does not
/// truncate a block early.
fn top_level_blocks<'a>(xml: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let mut depth = 0usize;
    let mut block_start = 0usize;
    let mut pos = 0usize;

    while pos < xml.len() {
        let rest = &xml[pos..];
        if rest.starts_with(open) {
            if depth == 0 {
                block_start = pos + open.len();
            }
            depth += 1;
            pos += open.len();
        } else if rest.starts_with(close) {
            if depth == 1 {
                blocks.push(&xml[block_start..pos]);
            }
            depth = depth.saturating_sub(1);
            pos += close.len();
        } else {
            pos += 1;
        }
    }

    blocks
}

/// Parse the `<tagSet>` of an instance item into a key/value map.
///
/// Tags missing a key or value are omitted.
fn parse_tag_set(instance_item: &str) -> std::collections::HashMap<String, String> {
    let mut tags = std::collections::HashMap::new();

    for tag_item in top_level_blocks(instance_item, "<item>", "</item>") {
        if let (Some(key), Some(value)) = (
            parse_first_tag_value(tag_item, "key"),
            parse_first_tag_value(tag_item, "value"),
        ) {
            tags.insert(key, value);
        }
    }

    tags
}

/// Extract security groups from a DescribeSecurityGroups XML response. A
/// group's own `groupId` precedes its rules, whose `groups` items name other
/// groups; its tags are those of its `tagSet`.
fn parse_security_groups(xml: &str) -> Vec<SecurityGroup> {
    let mut groups = Vec::new();

    for info in top_level_blocks(xml, "<securityGroupInfo>", "</securityGroupInfo>") {
        for item in top_level_blocks(info, "<item>", "</item>") {
            let head = item
                .split_once("<ipPermissions")
                .map_or(item, |(head, _)| head);
            let Some(group_id) = parse_first_tag_value(head, "groupId") else {
                continue;
            };
            let tags = top_level_blocks(item, "<tagSet>", "</tagSet>")
                .first()
                .map(|tag_set| parse_tag_set(tag_set))
                .unwrap_or_default();
            groups.push(SecurityGroup { group_id, tags });
        }
    }

    groups
}

#[tracing::instrument(skip_all, err)]
fn parse_app_address(xml: &str) -> Result<(String, String, Option<String>), ParseAppAddressError> {
    let allocation_ids = parse_tag_values(xml, "allocationId");
    let public_ips = parse_tag_values(xml, "publicIp");
    if allocation_ids.len() != 1 || public_ips.len() != 1 {
        return Err(ParseAppAddressError::NotExactlyOne {
            location: std::panic::Location::caller(),
        });
    }
    // An unassociated address may carry an empty `<instanceId></instanceId>`.
    Ok((
        allocation_ids[0].clone(),
        public_ips[0].clone(),
        parse_first_tag_value(xml, "instanceId").filter(|id| !id.is_empty()),
    ))
}

/// Absence is confirmed only by `InvalidInstanceID.NotFound` or a response
/// listing no instance. A false `None` would mark a runtime lost, which stops
/// its billing and blocks switching back to it.
fn instance_runtime(
    response: Result<String, SignedRequestError>,
) -> Result<Option<InstanceRuntime>, DescribeInstanceRuntimeError> {
    use DescribeInstanceRuntimeErrorCtx as Ctx;

    match response {
        Ok(body) => parse_instance_runtime(&body).with_context(Ctx::parse()),
        Err(SignedRequestError::NonSuccess {
            aws_code: Some(code),
            ..
        }) if code == "InvalidInstanceID.NotFound" => Ok(None),
        Err(error) => Err(error).with_context(Ctx::request()),
    }
}

/// Runtime of the first instance in a DescribeInstances response; `None` only
/// when its reservation set lists no instance.
fn parse_instance_runtime(xml: &str) -> Result<Option<InstanceRuntime>, ParseInstanceRuntimeError> {
    let reservations = if xml.contains("<reservationSet/>") {
        ""
    } else {
        xml.split_once("<reservationSet>")
            .and_then(|(_, rest)| rest.rsplit_once("</reservationSet>"))
            .map(|(reservations, _)| reservations)
            .ok_or_else(|| ParseInstanceRuntimeError::NoReservationSet {
                location: std::panic::Location::caller(),
            })?
    };
    if !reservations.contains("<instanceId>") {
        return Ok(None);
    }
    let state = reservations
        .split_once("<instanceState>")
        .and_then(|(_, rest)| rest.split_once("</instanceState>"))
        .and_then(|(state_block, _)| parse_first_tag_value(state_block, "name"))
        .filter(|state| !state.is_empty())
        .ok_or_else(|| ParseInstanceRuntimeError::NoState {
            location: std::panic::Location::caller(),
        })?;
    Ok(Some(InstanceRuntime {
        state,
        public_ip: parse_first_tag_value(reservations, "ipAddress"),
    }))
}

fn parse_first_tag_value(xml: &str, tag_name: &str) -> Option<String> {
    parse_tag_values(xml, tag_name).into_iter().next()
}

fn parse_tag_values(xml: &str, tag_name: &str) -> Vec<String> {
    let tag = format!("<{}>", tag_name);
    let end_tag = format!("</{}>", tag_name);
    let mut values = Vec::new();
    let mut pos = 0;

    while let Some(start) = xml[pos..].find(&tag) {
        let start = pos + start + tag.len();
        if let Some(end) = xml[start..].find(&end_tag) {
            values.push(xml[start..start + end].to_string());
            pos = start + end + end_tag.len();
        } else {
            break;
        }
    }

    values
}

/// `subnetId` to `availabilityZone` in a DescribeSubnets response: each subnet
/// item holds one of each (`availabilityZoneId` is another tag).
fn parse_subnet_zones(xml: &str) -> std::collections::HashMap<String, String> {
    parse_tag_values(xml, "subnetId")
        .into_iter()
        .zip(parse_tag_values(xml, "availabilityZone"))
        .collect()
}

fn parse_images(xml: &str) -> Vec<Image> {
    let image_ids = parse_tag_values(xml, "imageId");
    let creation_dates = parse_tag_values(xml, "creationDate");

    image_ids
        .into_iter()
        .zip(creation_dates)
        .map(|(image_id, creation_date)| Image {
            image_id,
            creation_date,
        })
        .collect()
}

fn parse_regions(xml: &str) -> Vec<Region> {
    let mut regions = Vec::new();
    let mut pos = 0;

    while let Some(item_start) = xml[pos..].find("<item>") {
        let item_start = pos + item_start + "<item>".len();
        let Some(item_end) = xml[item_start..].find("</item>") else {
            break;
        };
        let item = &xml[item_start..item_start + item_end];

        if let Some(name) = parse_first_tag_value(item, "regionName") {
            regions.push(Region {
                name,
                opt_in_status: parse_first_tag_value(item, "optInStatus"),
            });
        }

        pos = item_start + item_end + "</item>".len();
    }

    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param_value<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|(param_key, _)| param_key == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn subnet_zones_pair_each_subnet_with_its_zone() {
        let xml = "<DescribeSubnetsResponse><subnetSet>\
            <item><subnetId>subnet-a</subnetId><availabilityZone>us-east-1a</availabilityZone>\
            <availabilityZoneId>use1-az1</availabilityZoneId><subnetArn>arn:subnet-a</subnetArn></item>\
            <item><subnetId>subnet-b</subnetId><availabilityZone>us-east-1b</availabilityZone>\
            <availabilityZoneId>use1-az2</availabilityZoneId></item>\
            </subnetSet></DescribeSubnetsResponse>";
        let zones = parse_subnet_zones(xml);
        assert_eq!(zones.len(), 2);
        assert_eq!(zones["subnet-a"], "us-east-1a");
        assert_eq!(zones["subnet-b"], "us-east-1b");
    }

    #[test]
    fn test_parse_instance_ids() {
        let xml = r#"
        <DescribeInstancesResponse>
          <reservationSet>
            <item>
              <instancesSet>
                <item>
                  <instanceId>i-1234567890abcdef0</instanceId>
                </item>
              </instancesSet>
            </item>
            <item>
              <instancesSet>
                <item>
                  <instanceId>i-abcdef1234567890</instanceId>
                </item>
              </instancesSet>
            </item>
          </reservationSet>
        </DescribeInstancesResponse>"#;

        let instances = parse_instance_ids(xml);
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].instance_id, "i-1234567890abcdef0");
        assert_eq!(instances[1].instance_id, "i-abcdef1234567890");
    }

    #[test]
    fn test_parse_empty_response() {
        let xml = r#"
        <DescribeInstancesResponse>
          <reservationSet/>
        </DescribeInstancesResponse>"#;

        let instances = parse_instance_ids(xml);
        assert!(instances.is_empty());
    }

    #[test]
    fn test_parse_instance_tags_grouped_per_instance() {
        let xml = r#"
        <DescribeInstancesResponse>
          <reservationSet>
            <item>
              <instancesSet>
                <item>
                  <instanceId>i-aaaa1111</instanceId>
                  <instanceType>c5.xlarge</instanceType>
                  <tagSet>
                    <item><key>Name</key><value>caution-builder-aaaa1111</value></item>
                    <item><key>org_id</key><value>11111111-1111-1111-1111-111111111111</value></item>
                  </tagSet>
                </item>
                <item>
                  <instanceId>i-bbbb2222</instanceId>
                  <instanceType>m5.large</instanceType>
                  <tagSet>
                    <item><key>Name</key><value>caution-builder-bbbb2222</value></item>
                  </tagSet>
                </item>
              </instancesSet>
            </item>
          </reservationSet>
        </DescribeInstancesResponse>"#;

        let instances = parse_instance_ids(xml);
        assert_eq!(instances.len(), 2);

        assert_eq!(instances[0].instance_id, "i-aaaa1111");
        assert_eq!(instances[0].instance_type.as_deref(), Some("c5.xlarge"));
        assert_eq!(
            instances[0].tags.get("org_id").map(String::as_str),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            instances[0].tags.get("Name").map(String::as_str),
            Some("caution-builder-aaaa1111")
        );

        assert_eq!(instances[1].instance_id, "i-bbbb2222");
        assert_eq!(
            instances[1].tags.get("Name").map(String::as_str),
            Some("caution-builder-bbbb2222")
        );
        assert!(
            !instances[1].tags.contains_key("org_id"),
            "tags from one instance must not bleed into another"
        );
    }

    #[test]
    fn test_parse_instance_without_tags() {
        let xml = r#"
        <DescribeInstancesResponse>
          <reservationSet>
            <item>
              <instancesSet>
                <item>
                  <instanceId>i-cccc3333</instanceId>
                  <tagSet/>
                </item>
              </instancesSet>
            </item>
          </reservationSet>
        </DescribeInstancesResponse>"#;

        let instances = parse_instance_ids(xml);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "i-cccc3333");
        assert!(instances[0].tags.is_empty());
    }

    #[test]
    fn security_groups_keep_their_own_id_and_tags() {
        let xml = r#"
        <DescribeSecurityGroupsResponse>
          <securityGroupInfo>
            <item>
              <ownerId>123456789012</ownerId>
              <groupId>sg-aaaa1111</groupId>
              <groupName>enclave-1</groupName>
              <ipPermissions>
                <item>
                  <ipProtocol>tcp</ipProtocol>
                  <groups>
                    <item><userId>123456789012</userId><groupId>sg-other</groupId></item>
                  </groups>
                  <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>
                </item>
              </ipPermissions>
              <ipPermissionsEgress/>
              <tagSet>
                <item><key>ResourceId</key><value>app-1</value></item>
                <item><key>DeploymentId</key><value>deployment-1</value></item>
              </tagSet>
            </item>
            <item>
              <groupId>sg-bbbb2222</groupId>
              <ipPermissions/>
            </item>
          </securityGroupInfo>
        </DescribeSecurityGroupsResponse>"#;

        let groups = parse_security_groups(xml);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].group_id, "sg-aaaa1111");
        assert_eq!(groups[0].tags.len(), 2);
        assert_eq!(
            groups[0].tags.get("DeploymentId").map(String::as_str),
            Some("deployment-1")
        );
        assert_eq!(groups[1].group_id, "sg-bbbb2222");
        assert!(groups[1].tags.is_empty());
        assert!(parse_security_groups("<securityGroupInfo/>").is_empty());
    }

    #[test]
    fn test_parse_app_address() {
        let xml = "<item><allocationId>eipalloc-123</allocationId><publicIp>198.51.100.42</publicIp><instanceId>i-123</instanceId></item>";
        let address = parse_app_address(xml).unwrap();

        assert_eq!(address.0, "eipalloc-123");
        assert_eq!(address.1, "198.51.100.42");
        assert_eq!(address.2.as_deref(), Some("i-123"));
    }

    #[test]
    fn unassociated_app_address_has_no_holder() {
        let empty = "<item><allocationId>eipalloc-123</allocationId><publicIp>198.51.100.42</publicIp><instanceId></instanceId></item>";
        let absent = "<item><allocationId>eipalloc-123</allocationId><publicIp>198.51.100.42</publicIp></item>";
        assert_eq!(parse_app_address(empty).unwrap().2, None);
        assert_eq!(parse_app_address(absent).unwrap().2, None);
    }

    #[test]
    fn instance_runtime_parses_state_and_public_ip() {
        let xml = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item>\
            <instanceId>i-0abc</instanceId><instanceState><code>16</code><name>running</name></instanceState>\
            <ipAddress>203.0.113.9</ipAddress><tagSet><item><key>Name</key><value>x</value></item></tagSet>\
            </item></instancesSet></item></reservationSet></DescribeInstancesResponse>";
        let runtime = parse_instance_runtime(xml).unwrap().unwrap();
        assert_eq!(runtime.state, "running");
        assert_eq!(runtime.public_ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn instance_runtime_without_public_ip_or_instances() {
        let stopped = "<reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId>\
            <instanceState><code>80</code><name>stopped</name></instanceState></item></instancesSet>\
            </item></reservationSet>";
        assert_eq!(
            parse_instance_runtime(stopped).unwrap().unwrap().public_ip,
            None
        );
        for empty in [
            "<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>",
            "<DescribeInstancesResponse><reservationSet>\n </reservationSet></DescribeInstancesResponse>",
            "<reservationSet><item><reservationId>r-1</reservationId><instancesSet/></item></reservationSet>",
        ] {
            assert_eq!(parse_instance_runtime(empty).unwrap(), None, "{empty}");
        }
    }

    /// A false "gone" stops billing and blocks switching back (`runtime_lost`).
    #[test]
    fn instance_runtime_is_absent_only_when_confirmed() {
        let not_found = signed_request_non_success(
            "ec2",
            400,
            "<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code></Error></Errors></Response>",
        );
        assert_eq!(instance_runtime(Err(not_found)).unwrap(), None);
        let malformed = signed_request_non_success(
            "ec2",
            400,
            "<Response><Errors><Error><Code>InvalidInstanceID.Malformed</Code></Error></Errors></Response>",
        );
        assert!(matches!(
            instance_runtime(Err(malformed)),
            Err(DescribeInstanceRuntimeError::Request { .. })
        ));
        let unavailable = signed_request_non_success("ec2", 503, "<html>unavailable</html>");
        assert!(instance_runtime(Err(unavailable)).is_err());

        // A 200 that lists an instance it cannot read, or is no DescribeInstances
        // response (including a truncated one), is an error, never `None`.
        for unreadable in [
            "<reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId>\
             </item></instancesSet></item></reservationSet>",
            "<reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId>\
             <instanceState><name></name></instanceState></item></instancesSet></item></reservationSet>",
            "<reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId>",
            "<html>ok</html>",
            "",
        ] {
            assert!(
                matches!(
                    instance_runtime(Ok(unreadable.to_string())),
                    Err(DescribeInstanceRuntimeError::Parse { .. })
                ),
                "{unreadable}"
            );
        }
    }

    #[test]
    fn non_success_carries_the_aws_error_code() {
        let body = "<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code>\
            <Message>The instance ID 'i-0abc' does not exist</Message></Error></Errors>\
            <RequestID>r-1</RequestID></Response>";
        let error = signed_request_non_success("ec2", 400, body);
        assert!(matches!(
            &error,
            SignedRequestError::NonSuccess { aws_code: Some(code), status: 400, .. }
                if code == "InvalidInstanceID.NotFound"
        ));
        // The code is carried as data; the message stays as before.
        assert!(error.to_string().starts_with("ec2 API returned 400 ["));

        let opaque = signed_request_non_success("ec2", 503, "<html>unavailable</html>");
        assert!(matches!(
            opaque,
            SignedRequestError::NonSuccess { aws_code: None, .. }
        ));
    }

    fn app_address(instance_id: Option<&str>) -> AppAddress {
        AppAddress {
            allocation_id: "eipalloc-1".to_string(),
            public_ip: "198.51.100.42".to_string(),
            instance_id: instance_id.map(str::to_string),
        }
    }

    #[test]
    fn move_is_idempotent_when_target_already_holds_the_address() {
        let address = app_address(Some("i-new"));
        // Idempotent even when the caller's expectation is stale.
        for expected in [None, Some("i-old"), Some("i-new")] {
            assert_eq!(
                plan_app_address_move(&address, "i-new", expected).unwrap(),
                AppAddressMove::AlreadyAtTarget
            );
        }
    }

    #[test]
    fn move_refuses_an_unexpected_holder() {
        let held = app_address(Some("i-other"));
        let unassociated = app_address(None);
        for (address, expected) in [
            (&held, Some("i-old")),
            (&held, None),
            (&unassociated, Some("i-old")),
        ] {
            let error = plan_app_address_move(address, "i-new", expected).unwrap_err();
            assert!(
                matches!(
                    &error,
                    MoveAppAddressError::HolderMismatch { expected: e, actual: a, .. }
                        if e.as_deref() == expected && *a == address.instance_id
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn move_only_allows_reassociation_from_an_expected_holder() {
        assert_eq!(
            plan_app_address_move(&app_address(None), "i-new", None).unwrap(),
            AppAddressMove::Associate {
                allow_reassociation: false
            }
        );
        assert_eq!(
            plan_app_address_move(&app_address(Some("i-old")), "i-new", Some("i-old")).unwrap(),
            AppAddressMove::Associate {
                allow_reassociation: true
            }
        );
    }

    #[test]
    fn associate_address_params_mirror_the_app_address_association() {
        let params = associate_address_params("eipalloc-1", "i-new", false);
        assert_eq!(param_value(&params, "Action"), Some("AssociateAddress"));
        assert_eq!(param_value(&params, "AllocationId"), Some("eipalloc-1"));
        assert_eq!(param_value(&params, "InstanceId"), Some("i-new"));
        assert_eq!(param_value(&params, "AllowReassociation"), Some("false"));
        let params = associate_address_params("eipalloc-1", "i-new", true);
        assert_eq!(param_value(&params, "AllowReassociation"), Some("true"));
    }

    #[test]
    fn test_parse_first_tag_value() {
        let xml = r#"
        <DescribeSecurityGroupsResponse>
          <securityGroupInfo>
            <item>
              <groupId>sg-1234567890abcdef0</groupId>
              <groupName>default</groupName>
            </item>
          </securityGroupInfo>
        </DescribeSecurityGroupsResponse>"#;

        assert_eq!(
            parse_first_tag_value(xml, "groupId").as_deref(),
            Some("sg-1234567890abcdef0")
        );
    }

    #[test]
    fn test_parse_images() {
        let xml = r#"
        <DescribeImagesResponse>
          <imagesSet>
            <item>
              <imageId>ami-old</imageId>
              <creationDate>2025-01-01T00:00:00.000Z</creationDate>
            </item>
            <item>
              <imageId>ami-new</imageId>
              <creationDate>2025-02-01T00:00:00.000Z</creationDate>
            </item>
          </imagesSet>
        </DescribeImagesResponse>"#;

        let images = parse_images(xml);
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].image_id, "ami-old");
        assert_eq!(images[1].creation_date, "2025-02-01T00:00:00.000Z");
    }

    #[test]
    fn test_parse_regions() {
        let xml = r#"
        <DescribeRegionsResponse>
          <regionInfo>
            <item>
              <regionName>us-east-1</regionName>
              <regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint>
              <optInStatus>opt-in-not-required</optInStatus>
            </item>
            <item>
              <regionName>ap-south-2</regionName>
              <regionEndpoint>ec2.ap-south-2.amazonaws.com</regionEndpoint>
              <optInStatus>not-opted-in</optInStatus>
            </item>
            <item>
              <regionName>us-west-2</regionName>
              <regionEndpoint>ec2.us-west-2.amazonaws.com</regionEndpoint>
            </item>
          </regionInfo>
        </DescribeRegionsResponse>"#;

        let regions = parse_regions(xml);
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].name, "us-east-1");
        assert_eq!(
            regions[0].opt_in_status.as_deref(),
            Some("opt-in-not-required")
        );
        assert_eq!(regions[1].name, "ap-south-2");
        assert_eq!(regions[1].opt_in_status.as_deref(), Some("not-opted-in"));
        assert_eq!(regions[2].name, "us-west-2");
        assert_eq!(regions[2].opt_in_status, None);
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(
            url_encode("tag:aws:autoscaling:groupName"),
            "tag%3Aaws%3Aautoscaling%3AgroupName"
        );
        assert_eq!(url_encode("running"), "running");
    }

    #[test]
    fn test_encode_form() {
        let params = vec![
            ("Action".to_string(), "DescribeInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        assert_eq!(
            encode_form(&params),
            "Action=DescribeInstances&Version=2016-11-15"
        );
    }

    #[test]
    fn test_run_instances_requires_imdsv2_with_one_hop_limit() {
        let params = RunInstancesParams {
            image_id: "ami-123".to_string(),
            instance_type: "c5.xlarge".to_string(),
            user_data: "#!/bin/sh\n".to_string(),
            iam_instance_profile: "builder-profile".to_string(),
            security_group_ids: vec!["sg-123".to_string()],
            subnet_id: "subnet-123".to_string(),
            tags: vec![("ManagedBy".to_string(), "caution-builder".to_string())],
        };

        let req_params = run_instances_request_params(&params);

        assert_eq!(
            param_value(&req_params, "MetadataOptions.HttpTokens"),
            Some("required")
        );
        assert_eq!(
            param_value(&req_params, "MetadataOptions.HttpPutResponseHopLimit"),
            Some("1")
        );
        assert_eq!(
            param_value(&req_params, "SecurityGroupId.1"),
            Some("sg-123")
        );
        assert_eq!(
            param_value(&req_params, "TagSpecification.1.Tag.1.Key"),
            Some("ManagedBy")
        );
    }

    #[test]
    fn test_create_security_group_uses_group_description_param() {
        let params = vec![
            ("Action".to_string(), "CreateSecurityGroup".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            (
                "GroupName".to_string(),
                "caution-builder-dep-123".to_string(),
            ),
            (
                "GroupDescription".to_string(),
                "Security group for Caution builder deployment dep-123".to_string(),
            ),
            ("VpcId".to_string(), "vpc-123".to_string()),
        ];

        let encoded = encode_form(&params);
        assert!(encoded.contains("Action=CreateSecurityGroup"));
        assert!(encoded.contains(
            "GroupDescription=Security%20group%20for%20Caution%20builder%20deployment%20dep-123"
        ));
        assert!(
            encoded
                .split('&')
                .all(|param| !param.starts_with("Description="))
        );
    }

    // Verify stop/start param construction by testing the pattern they use
    // (same approach as testing describe_instances params via encode_form)

    #[test]
    fn test_stop_instances_params_single() {
        let mut params = vec![
            ("Action".to_string(), "StopInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        let instance_ids = ["i-abc123".to_string()];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }

        let encoded = encode_form(&params);
        assert!(encoded.contains("Action=StopInstances"));
        assert!(encoded.contains("InstanceId.1=i-abc123"));
    }

    #[test]
    fn test_stop_instances_params_multiple() {
        let mut params = vec![
            ("Action".to_string(), "StopInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        let instance_ids = [
            "i-aaa111".to_string(),
            "i-bbb222".to_string(),
            "i-ccc333".to_string(),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }

        let encoded = encode_form(&params);
        assert!(encoded.contains("Action=StopInstances"));
        assert!(encoded.contains("InstanceId.1=i-aaa111"));
        assert!(encoded.contains("InstanceId.2=i-bbb222"));
        assert!(encoded.contains("InstanceId.3=i-ccc333"));
        // Verify correct 1-based indexing (not 0-based)
        assert!(!encoded.contains("InstanceId.0"));
    }

    #[test]
    fn test_start_instances_params_single() {
        let mut params = vec![
            ("Action".to_string(), "StartInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        let instance_ids = ["i-xyz789".to_string()];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }

        let encoded = encode_form(&params);
        assert!(encoded.contains("Action=StartInstances"));
        assert!(encoded.contains("InstanceId.1=i-xyz789"));
    }

    #[test]
    fn test_stop_instances_params_empty() {
        let mut params = vec![
            ("Action".to_string(), "StopInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        let instance_ids: Vec<String> = vec![];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }

        let encoded = encode_form(&params);
        assert_eq!(encoded, "Action=StopInstances&Version=2016-11-15");
        assert!(!encoded.contains("InstanceId"));
    }

    #[test]
    fn test_derive_signing_key() {
        // Just verify it doesn't panic and returns 32 bytes (SHA-256 output)
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20240101",
            "us-east-1",
            "ec2",
        );
        assert_eq!(key.len(), 32);

        let key2 = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20240101",
            "us-east-1",
            "autoscaling",
        );
        assert_eq!(key2.len(), 32);
        assert_ne!(key, key2);
    }
}

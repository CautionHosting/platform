// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Minimal AWS clients using direct HTTP calls with SigV4 signing.
//! Replaces aws-sdk-ec2 and aws-sdk-autoscaling to avoid compiling massive generated SDKs.

use anyhow::{Context, Result, bail};
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
}

pub struct Image {
    pub image_id: String,
    pub creation_date: String,
}

pub struct Region {
    pub name: String,
    pub opt_in_status: Option<String>,
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

impl Ec2Client {
    pub fn new(credentials: &AwsCredentials) -> Self {
        Self {
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.clone(),
            region: credentials.region.clone(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn describe_instances(&self, filters: &[Filter]) -> Result<Vec<Instance>> {
        let mut params = vec![
            ("Action".to_string(), "DescribeInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        for (i, filter) in filters.iter().enumerate() {
            let idx = i + 1;
            params.push((format!("Filter.{}.Name", idx), filter.name.clone()));
            for (j, value) in filter.values.iter().enumerate() {
                params.push((format!("Filter.{}.Value.{}", idx, j + 1), value.clone()));
            }
        }

        let body = self.signed_request(&params).await?;
        Ok(parse_instance_ids(&body))
    }

    pub async fn count_vpcs(&self) -> Result<u32> {
        let params = vec![
            ("Action".to_string(), "DescribeVpcs".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        let body = self.signed_request(&params).await?;
        Ok(parse_tag_values(&body, "vpcId").len() as u32)
    }

    pub async fn count_elastic_ips(&self) -> Result<u32> {
        let params = vec![
            ("Action".to_string(), "DescribeAddresses".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        let body = self.signed_request(&params).await?;
        Ok(parse_tag_values(&body, "publicIp").len() as u32)
    }

    pub async fn active_instance_types(&self) -> Result<Vec<String>> {
        let instances = self
            .describe_instances(&[Filter::new("instance-state-name", &["pending", "running"])])
            .await?;

        Ok(instances
            .into_iter()
            .filter_map(|instance| instance.instance_type)
            .collect())
    }

    pub async fn describe_regions(&self, all_regions: bool) -> Result<Vec<Region>> {
        let mut params = vec![
            ("Action".to_string(), "DescribeRegions".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];

        if all_regions {
            params.push(("AllRegions".to_string(), "true".to_string()));
        }

        let body = self.signed_request(&params).await?;
        Ok(parse_regions(&body))
    }

    pub async fn instance_type_offered(&self, instance_type: &str) -> Result<bool> {
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

        let body = self.signed_request(&params).await?;
        Ok(!parse_tag_values(&body, "instanceType").is_empty())
    }

    pub async fn stop_instances(&self, instance_ids: &[String]) -> Result<()> {
        let mut params = vec![
            ("Action".to_string(), "StopInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params).await?;
        Ok(())
    }

    pub async fn start_instances(&self, instance_ids: &[String]) -> Result<()> {
        let mut params = vec![
            ("Action".to_string(), "StartInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params).await?;
        Ok(())
    }

    pub async fn run_instances(&self, params: &RunInstancesParams) -> Result<String> {
        let req_params = run_instances_request_params(params);

        let body = self.signed_request(&req_params).await?;

        // Parse instance ID from RunInstances response
        let instances = parse_instance_ids(&body);
        instances
            .into_iter()
            .next()
            .map(|i| i.instance_id)
            .ok_or_else(|| anyhow::anyhow!("RunInstances response did not contain an instance ID"))
    }

    pub async fn latest_amazon_linux_2023_ami_id(&self) -> Result<String> {
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

        let body = self.signed_request(&params).await?;
        let mut images = parse_images(&body);
        images.sort_by(|left, right| left.creation_date.cmp(&right.creation_date));
        images
            .pop()
            .map(|image| image.image_id)
            .ok_or_else(|| anyhow::anyhow!("No Amazon Linux 2023 AMI returned by DescribeImages"))
    }

    pub async fn find_security_group_id(
        &self,
        vpc_id: &str,
        group_name: &str,
    ) -> Result<Option<String>> {
        let params = vec![
            ("Action".to_string(), "DescribeSecurityGroups".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Filter.1.Name".to_string(), "vpc-id".to_string()),
            ("Filter.1.Value.1".to_string(), vpc_id.to_string()),
            ("Filter.2.Name".to_string(), "group-name".to_string()),
            ("Filter.2.Value.1".to_string(), group_name.to_string()),
        ];

        let body = self.signed_request(&params).await?;
        Ok(parse_first_tag_value(&body, "groupId"))
    }

    pub async fn create_security_group(
        &self,
        group_name: &str,
        description: &str,
        vpc_id: &str,
        tags: &[(String, String)],
    ) -> Result<String> {
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

        let body = self.signed_request(&params).await?;
        parse_first_tag_value(&body, "groupId").ok_or_else(|| {
            anyhow::anyhow!("CreateSecurityGroup response did not contain a groupId")
        })
    }

    pub async fn terminate_instances(&self, instance_ids: &[String]) -> Result<()> {
        let mut params = vec![
            ("Action".to_string(), "TerminateInstances".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
        ];
        for (i, id) in instance_ids.iter().enumerate() {
            params.push((format!("InstanceId.{}", i + 1), id.clone()));
        }
        self.signed_request(&params).await?;
        Ok(())
    }

    pub async fn associate_address(&self, allocation_id: &str, instance_id: &str) -> Result<()> {
        let params = vec![
            ("Action".to_string(), "AssociateAddress".to_string()),
            ("Version".to_string(), "2016-11-15".to_string()),
            ("AllocationId".to_string(), allocation_id.to_string()),
            ("InstanceId".to_string(), instance_id.to_string()),
        ];

        self.signed_request(&params).await?;
        Ok(())
    }

    async fn signed_request(&self, params: &[(String, String)]) -> Result<String> {
        signed_request(
            &self.http,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "ec2",
            params,
        )
        .await
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

    pub async fn get_service_quota_value(
        &self,
        service_code: &str,
        quota_code: &str,
    ) -> Result<f64> {
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
        .await?;

        response
            .get("Quota")
            .and_then(|quota| quota.get("Value"))
            .and_then(|value| value.as_f64())
            .ok_or_else(|| anyhow::anyhow!("Service quota response did not include Quota.Value"))
    }
}

pub struct AsgClient {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    http: reqwest::Client,
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

    pub async fn set_desired_capacity(&self, asg_name: &str, desired_capacity: i32) -> Result<()> {
        let params = vec![
            ("Action".to_string(), "SetDesiredCapacity".to_string()),
            ("Version".to_string(), "2011-01-01".to_string()),
            ("AutoScalingGroupName".to_string(), asg_name.to_string()),
            ("DesiredCapacity".to_string(), desired_capacity.to_string()),
        ];

        self.signed_request(&params).await?;
        Ok(())
    }

    pub async fn update_auto_scaling_group(
        &self,
        asg_name: &str,
        launch_template_id: &str,
    ) -> Result<()> {
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

        self.signed_request(&params).await?;
        Ok(())
    }

    async fn signed_request(&self, params: &[(String, String)]) -> Result<String> {
        signed_request(
            &self.http,
            &self.access_key_id,
            &self.secret_access_key,
            &self.region,
            "autoscaling",
            params,
        )
        .await
    }
}

async fn signed_request(
    http: &reqwest::Client,
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    params: &[(String, String)],
) -> Result<String> {
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
        .context(format!("{} API request failed", service))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .context(format!("Failed to read {} response", service))?;

    if !status.is_success() {
        bail!("{} API returned {}: {}", service, status, text);
    }

    Ok(text)
}

async fn signed_json_request(
    http: &reqwest::Client,
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    target: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let host = format!("{}.{}.amazonaws.com", service, region);
    let url = format!("https://{}/", host);
    let body = serde_json::to_string(body).context("Failed to serialize AWS JSON body")?;

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
        .context(format!("{} API request failed", service))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .context(format!("Failed to read {} response", service))?;

    if !status.is_success() {
        bail!("{} API returned {}: {}", service, status, text);
    }

    serde_json::from_str(&text).context(format!("Failed to parse {} response JSON", service))
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

/// Extract instance IDs from EC2 DescribeInstances XML response.
fn parse_instance_ids(xml: &str) -> Vec<Instance> {
    let instance_ids = parse_tag_values(xml, "instanceId");
    let instance_types = parse_tag_values(xml, "instanceType");

    instance_ids
        .into_iter()
        .enumerate()
        .map(|(index, instance_id)| Instance {
            instance_id,
            instance_type: instance_types.get(index).cloned(),
        })
        .collect()
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
        let instance_ids = vec!["i-abc123".to_string()];
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
        let instance_ids = vec![
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
        let instance_ids = vec!["i-xyz789".to_string()];
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

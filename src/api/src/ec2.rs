// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Minimal AWS clients using direct HTTP calls with SigV4 signing.
//! Replaces aws-sdk-ec2 and aws-sdk-autoscaling to avoid compiling massive generated SDKs.

use anyhow::{bail, Context, Result};
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
}

impl Filter {
    pub fn new(name: &str, values: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }
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
            // IMDSv2 required
            (
                "MetadataOptions.HttpTokens".to_string(),
                "required".to_string(),
            ),
            (
                "MetadataOptions.HttpPutResponseHopLimit".to_string(),
                "2".to_string(),
            ),
            // Encrypted root volume
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

        let body = self.signed_request(&req_params).await?;

        // Parse instance ID from RunInstances response
        let instances = parse_instance_ids(&body);
        instances
            .into_iter()
            .next()
            .map(|i| i.instance_id)
            .ok_or_else(|| anyhow::anyhow!("RunInstances response did not contain an instance ID"))
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
    let mut instances = Vec::new();
    let tag = "<instanceId>";
    let end_tag = "</instanceId>";
    let mut pos = 0;
    while let Some(start) = xml[pos..].find(tag) {
        let start = pos + start + tag.len();
        if let Some(end) = xml[start..].find(end_tag) {
            let id = &xml[start..start + end];
            instances.push(Instance {
                instance_id: id.to_string(),
            });
            pos = start + end + end_tag.len();
        } else {
            break;
        }
    }
    instances
}

#[cfg(test)]
mod tests {
    use super::*;

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
